import time
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


def generate_ecdh_keypair(curve_name="P-256"):
    if curve_name not in CURVES:
        raise ValueError(f"Unsupported curve. Choose from {list(CURVES.keys())}")
    private_key = ec.generate_private_key(curve=CURVES[curve_name], backend=default_backend())
    return private_key, private_key.public_key()


def perform_ecdh(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)


def derive_aes_key(shared_secret, salt=None, info=b"ecdh-aes-key"):
    if salt is None:
        salt = os.urandom(32)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)


def aes_gcm_encrypt(aes_key, plaintext):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def aes_gcm_decrypt(aes_key, nonce, ciphertext, tag):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def simulate_ecdh_handshake(curve_name="P-256", message=None):
    if message is None:
        message = os.urandom(1024)

    results = {"curve": curve_name, "message_size_bytes": len(message)}
    salt = os.urandom(32)

    t0 = time.perf_counter_ns()
    alice_priv, alice_pub = generate_ecdh_keypair(curve_name)
    bob_priv, bob_pub = generate_ecdh_keypair(curve_name)
    results["keygen_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    alice_shared = perform_ecdh(alice_priv, bob_pub)
    bob_shared = perform_ecdh(bob_priv, alice_pub)
    results["exchange_ms"] = (time.perf_counter_ns() - t0) / 1e6

    assert alice_shared == bob_shared, "ECDH shared secret mismatch!"
    results["shared_secret_bytes"] = len(alice_shared)

    alice_aes_key = derive_aes_key(alice_shared, salt)
    bob_aes_key = derive_aes_key(bob_shared, salt)
    assert alice_aes_key == bob_aes_key, "Derived AES keys differ!"
    results["derived_key_bytes"] = len(alice_aes_key)

    t0 = time.perf_counter_ns()
    nonce, ciphertext, tag = aes_gcm_encrypt(alice_aes_key, message)
    results["encrypt_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    decrypted = aes_gcm_decrypt(bob_aes_key, nonce, ciphertext, tag)
    results["decrypt_ms"] = (time.perf_counter_ns() - t0) / 1e6

    results["success"] = decrypted == message
    results["ciphertext_bytes"] = len(ciphertext)

    pub_bytes = alice_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    results["public_key_bytes"] = len(pub_bytes)

    return results


def run_ecdh(curve_name="P-256", iterations=100):
    message = os.urandom(256)
    totals = {k: 0.0 for k in ["keygen_ms", "exchange_ms", "encrypt_ms", "decrypt_ms"]}

    for _ in range(iterations):
        r = simulate_ecdh_handshake(curve_name, message)
        for k in totals:
            totals[k] += r[k]

    averages = {k: v / iterations for k, v in totals.items()}
    averages["curve"] = curve_name

    r = simulate_ecdh_handshake(curve_name, message)
    averages["public_key_bytes"] = r["public_key_bytes"]
    averages["shared_secret_bytes"] = r["shared_secret_bytes"]
    averages["ciphertext_bytes"] = r["ciphertext_bytes"]

    return averages


if __name__ == "__main__":
    print("=" * 60)
    print("      ECDH KEY EXCHANGE — CLASSICAL CRYPTOGRAPHY DEMO")
    print("=" * 60)

    for curve_name in ["P-256", "P-384", "P-521"]:
        print(f"\n🤝 ECDH Handshake ({curve_name})")
        print("-" * 45)

        result = simulate_ecdh_handshake(curve_name)

        print(f"  Key Generation       : {result['keygen_ms']:.4f} ms (both parties)")
        print(f"  Key Exchange         : {result['exchange_ms']:.4f} ms")
        print(f"  Encrypt (AES-GCM)    : {result['encrypt_ms']:.4f} ms")
        print(f"  Decrypt (AES-GCM)    : {result['decrypt_ms']:.4f} ms")
        print(f"  Public Key Size      : {result['public_key_bytes']} bytes  ← sent over wire")
        print(f"  Shared Secret Size   : {result['shared_secret_bytes']} bytes")
        print(f"  Derived AES Key      : {result['derived_key_bytes']} bytes (256-bit)")
        print(f"  Message Size         : {result['message_size_bytes']} bytes")
        print(f"  Ciphertext Size      : {result['ciphertext_bytes']} bytes")
        print(f"  Handshake Success    : {result['success']}")

    print("\n📐 Security Level Comparison")
    print("-" * 45)
    print(f"  {'Algorithm':<20} {'Classical Bits':<18} {'Quantum Bits (Shor)':<20}")
    print(f"  {'─'*18:<20} {'─'*14:<18} {'─'*18:<20}")
    security = [
        ("ECDH P-256",  "128-bit",  "~64-bit (broken)"),
        ("ECDH P-384",  "192-bit",  "~96-bit (broken)"),
        ("ECDH P-521",  "256-bit",  "~128-bit (broken)"),
        ("Kyber-512 *", "128-bit",  "128-bit (safe)"),
        ("Kyber-768 *", "192-bit",  "192-bit (safe)"),
    ]
    for algo, classical, quantum in security:
        print(f"  {algo:<20} {classical:<18} {quantum:<20}")
    print("\n  * See post_quantum/kyber_kem.py for Kyber implementation")

    print("\n✅ ECDH demo complete.\n")
