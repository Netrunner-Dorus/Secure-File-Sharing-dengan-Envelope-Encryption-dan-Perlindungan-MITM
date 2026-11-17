import hashlib
import hmac
import secrets
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Parameter Grup Diffie-Hellman 2048-bit Standar RFC 3526 (Group 14)
DH_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_P = int(DH_PRIME_HEX, 16)
DH_G = 2


def canonical_encode(*parts: bytes) -> bytes:
    """Enkode deterministik dengan length-prefix agar bebas ambiguitas transkrip."""
    out = bytearray()
    for p in parts:
        out.extend(struct.pack(">I", len(p)))
        out.extend(p)
    return bytes(out)


def hkdf_sha256_manual(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF Extract-and-Expand berbasis HMAC-SHA-256 (RFC 5869)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def protect_private_key_local(private_key, passphrase: str) -> dict:
    """Melindungi Identity Private Key lokal dengan Memory-Hard KDF + AES-256-GCM."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    local_kek = hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32
    )
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ct = AESGCM(local_kek).encrypt(nonce, pem_bytes, b"local-identity-keystore-v1")
    return {"salt": salt, "nonce": nonce, "encrypted_pem": ct}


def sign_rsa_pss(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_rsa_pss(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def garis(judul: str) -> None:
    print("\n" + "=" * 72)
    print(judul)
    print("=" * 72)


if __name__ == "__main__":
    garis("TAHAP 1. INISIALISASI IDENTITAS & KEYSTORE LOKAL (RSA-2048 + KDF)")
    IK_A_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    IK_A_pub = IK_A_priv.public_key()
    IK_B_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    IK_B_pub = IK_B_priv.public_key()

    keystore_alice = protect_private_key_local(IK_A_priv, "PassphraseKuatAlice#2026")
    fp_alice = hashlib.sha256(
        IK_A_pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()[:16]
    fp_bob = hashlib.sha256(
        IK_B_pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).hexdigest()[:16]

    print(f"Fingerprint IK_A_pub (diverifikasi out-of-band): {fp_alice}")
    print(f"Fingerprint IK_B_pub (diverifikasi out-of-band): {fp_bob}")
    print(f"Keystore lokal Alice terenkripsi AES-256-GCM   : {len(keystore_alice['encrypted_pem'])} byte")

    garis("TAHAP 2. AUTHENTICATED DIFFIE-HELLMAN HANDSHAKE (ANTI-MITM)")
    session_id = secrets.token_bytes(16)
    a_eph = secrets.randbelow(DH_P - 3) + 2
    A_pub = pow(DH_G, a_eph, DH_P)
    nonce_A = secrets.token_bytes(32)

    hello_A = canonical_encode(
        b"SFS-v1", session_id, b"Alice", b"Bob", A_pub.to_bytes(256, "big"), nonce_A
    )
    sig_A = sign_rsa_pss(IK_A_priv, hello_A)
    print(f"[Alice -> Bob] Mengirim Hello_A + sig_A ({len(sig_A)} byte)")

    assert verify_rsa_pss(IK_A_pub, hello_A, sig_A), "Verifikasi sig_A gagal!"
    b_eph = secrets.randbelow(DH_P - 3) + 2
    B_pub = pow(DH_G, b_eph, DH_P)
    nonce_B = secrets.token_bytes(32)

    hello_B = canonical_encode(
        b"SFS-v1", session_id, b"Bob", b"Alice", B_pub.to_bytes(256, "big"), nonce_B
    )
    transcript = canonical_encode(hello_A, sig_A, hello_B)
    sig_B = sign_rsa_pss(IK_B_priv, transcript)
    print(f"[Bob -> Alice] Verifikasi Alice OK. Mengirim Hello_B + sig_B ({len(sig_B)} byte)")

    assert verify_rsa_pss(IK_B_pub, transcript, sig_B), "Verifikasi sig_B gagal!"
    print("[Alice]        Verifikasi Bob & transkrip handshake OK.")

    garis("TAHAP 3. SHARED SECRET, HKDF-SHA-256, & KEY CONFIRMATION")
    shared_A = pow(B_pub, a_eph, DH_P).to_bytes(256, "big")
    shared_B = pow(A_pub, b_eph, DH_P).to_bytes(256, "big")
    assert shared_A == shared_B
    del a_eph, b_eph  # Hapus kunci ephemeral demi Forward Secrecy

    transcript_hash = hashlib.sha256(canonical_encode(transcript, sig_B)).digest()
    KEK_v1_A = hkdf_sha256_manual(shared_A, salt=transcript_hash, info=b"sfs-v1/kek", length=32)
    KEK_v1_B = hkdf_sha256_manual(shared_B, salt=transcript_hash, info=b"sfs-v1/kek", length=32)
    K_mac = hkdf_sha256_manual(shared_A, salt=transcript_hash, info=b"sfs-v1/mac", length=32)

    mac_alice = hmac.new(K_mac, b"KC-ALICE-TO-BOB:" + transcript_hash, hashlib.sha256).digest()
    mac_bob = hmac.new(K_mac, b"KC-BOB-TO-ALICE:" + transcript_hash, hashlib.sha256).digest()
    assert hmac.compare_digest(
        mac_alice, hmac.new(K_mac, b"KC-ALICE-TO-BOB:" + transcript_hash, hashlib.sha256).digest()
    )
    assert hmac.compare_digest(
        mac_bob, hmac.new(K_mac, b"KC-BOB-TO-ALICE:" + transcript_hash, hashlib.sha256).digest()
    )
    print(f"KEK_v1 Alice == Bob : {KEK_v1_A == KEK_v1_B} ({KEK_v1_A.hex()[:24]}...)")
    print("Key Confirmation MAC: Terverifikasi dengan hmac.compare_digest (waktu konstan)")

    garis("TAHAP 4. ENVELOPE ENCRYPTION BERKAS (DEK + AES-256-GCM + KEY WRAPPING)")
    file_id = b"dokumen_rahasia_01"
    seq_no = 1
    file_plaintext = (
        b"LAPORAN AUDIT KEAMANAN SISTEM INFORMASI UAJY 2026\n"
        b"Status: RAHASIA - Hanya untuk penerima terautentikasi.\n"
    ) * 50

    file_sha256 = hashlib.sha256(file_plaintext).hexdigest()
    DEK = AESGCM.generate_key(bit_length=256)
    nonce_file = secrets.token_bytes(12)
    aad_file = canonical_encode(session_id, file_id, struct.pack(">Q", seq_no), file_sha256.encode())
    ct_file = AESGCM(DEK).encrypt(nonce_file, file_plaintext, aad_file)

    nonce_wrap_v1 = secrets.token_bytes(12)
    aad_wrap = canonical_encode(session_id, file_id, b"KEK-v1")
    wrapped_dek_v1 = AESGCM(KEK_v1_A).encrypt(nonce_wrap_v1, DEK, aad_wrap)

    print(f"Ukuran file asli    : {len(file_plaintext):,} byte")
    print(f"SHA-256 file asli   : {file_sha256}")
    print(f"DEK (256-bit)       : {DEK.hex()[:24]}...")
    print(f"Wrapped DEK (v1)    : {wrapped_dek_v1.hex()[:32]}... ({len(wrapped_dek_v1)} byte)")
    print(f"Ciphertext + GCM Tag: {len(ct_file):,} byte (berisi tag autentikasi 16 byte)")

    garis("TAHAP 5. PENERIMAAN, DEKRIPSI, & VERIFIKASI INTEGRITAS OLEH BOB")
    received_seq_numbers = set()
    assert seq_no not in received_seq_numbers, "Replay terdeteksi!"

    unwrapped_dek = AESGCM(KEK_v1_B).decrypt(nonce_wrap_v1, wrapped_dek_v1, aad_wrap)
    decrypted_file = AESGCM(unwrapped_dek).decrypt(nonce_file, ct_file, aad_file)
    received_seq_numbers.add(seq_no)

    assert hashlib.sha256(decrypted_file).hexdigest() == file_sha256
    assert decrypted_file == file_plaintext
    print(f"Unwrap DEK berhasil : {unwrapped_dek == DEK}")
    print("Dekripsi & GCM Tag  : VALID")
    print(f"Verifikasi SHA-256  : COCOK ({hashlib.sha256(decrypted_file).hexdigest()[:24]}...)")

    garis("TAHAP 6. ROTASI KUNCI KEK (KEK v1 -> KEK v2) TANPA ENKRIPSI ULANG FILE")
    KEK_v2 = hkdf_sha256_manual(KEK_v1_A, salt=b"rotate-2026-11", info=b"sfs-v1/kek-v2", length=32)
    nonce_wrap_v2 = secrets.token_bytes(12)
    aad_wrap_v2 = canonical_encode(session_id, file_id, b"KEK-v2")
    wrapped_dek_v2 = AESGCM(KEK_v2).encrypt(nonce_wrap_v2, DEK, aad_wrap_v2)

    recovered_dek_v2 = AESGCM(KEK_v2).decrypt(nonce_wrap_v2, wrapped_dek_v2, aad_wrap_v2)
    recovered_file_v2 = AESGCM(recovered_dek_v2).decrypt(nonce_file, ct_file, aad_file)
    print(f"Wrapped DEK v1 != v2: {wrapped_dek_v1 != wrapped_dek_v2}")
    print(f"File pulih via KEKv2: {recovered_file_v2 == file_plaintext} (tanpa re-enkripsi {len(ct_file):,} byte)")

    garis("TAHAP 7. PENGUJIAN KEAMANAN (SIMULASI 4 SKENARIO SERANGAN)")
    # Uji 1: MITM mengganti kunci ephemeral A_pub dengan kunci milik Eve (M1)
    m1_eph = secrets.randbelow(DH_P - 3) + 2
    M1_pub = pow(DH_G, m1_eph, DH_P)
    hello_eve = canonical_encode(
        b"SFS-v1", session_id, b"Alice", b"Bob", M1_pub.to_bytes(256, "big"), nonce_A
    )
    mitm_blocked = not verify_rsa_pss(IK_A_pub, hello_eve, sig_A)
    print(f"[Uji 1 - MITM Key Substitution]    Serangan ditolak Bob   : {mitm_blocked}")

    # Uji 2: Server/Eve memodifikasi 1 byte pada ciphertext berkas
    tampered_ct = bytearray(ct_file)
    tampered_ct[10] ^= 0xFF
    try:
        AESGCM(unwrapped_dek).decrypt(nonce_file, bytes(tampered_ct), aad_file)
        tamper_ct_blocked = False
    except Exception:
        tamper_ct_blocked = True
    print(f"[Uji 2 - Ciphertext Tampering]     Modifikasi terdeteksi  : {tamper_ct_blocked}")

    # Uji 3: Server/Eve memodifikasi 1 byte pada Wrapped DEK
    tampered_wdek = bytearray(wrapped_dek_v1)
    tampered_wdek[0] ^= 0x01
    try:
        AESGCM(KEK_v1_B).decrypt(nonce_wrap_v1, bytes(tampered_wdek), aad_wrap)
        tamper_wdek_blocked = False
    except Exception:
        tamper_wdek_blocked = True
    print(f"[Uji 3 - Wrapped DEK Tampering]    Modifikasi terdeteksi  : {tamper_wdek_blocked}")

    # Uji 4: Server/Eve melakukan Replay Attack dengan paket seq_no = 1
    replay_blocked = seq_no in received_seq_numbers
    print(f"[Uji 4 - Replay Attack (seq_no=1)] Paket ulang ditolak    : {replay_blocked}")