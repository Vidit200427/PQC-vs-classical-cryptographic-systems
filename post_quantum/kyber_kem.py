import time
import os
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


KYBER_VARIANTS = {
    "Kyber512":  "Kyber512",
    "Kyber768":  "Kyber768",
    "Kyber1024": "Kyber1024",
}

KYBER_SECURITY_INFO = {
    "Kyber512":  {"nist_level": 1, "classical_equiv": "AES-128", "pq_secure": True},
    "Kyber768":  {"nist_level": 3, "classical_equiv": "AES-192", "pq_secure": True},
    "Kyber1024": {"nist_level": 5, "classical_equiv": "AES-256", "pq_secure": True},
}


def generate_kyber_keypair(variant="Kyber768"):
    if variant not in KYBER_VARIANTS:
        raise ValueError(f"Unknown variant '{variant}'. Choose from: {list(KYBER_VARIANTS.keys())}")
    kem = oqs.KeyEncapsulation(variant)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key, kem


def kyber_encapsulate(variant, public_key):
    with oqs.KeyEncapsulation(variant) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kyber_decapsulate(variant, private_key, ciphertext):
    with oqs.KeyEncapsulation(variant, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


def derive_aes_key(shared_secret, salt=None, info=b"kyber-aes-key"):
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


def simulate_kyber_handshake(variant="Kyber768", message=None):
    if message is None:
        message = os.urandom(1024)

    results = {"variant": variant, "message_size_bytes": len(message)}
    salt = os.urandom(32)

    t0 = time.perf_counter_ns()
    bob_pub, bob_priv, _ = generate_kyber_keypair(variant)
    results["keygen_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    ciphertext, alice_shared_secret = kyber_encapsulate(variant, bob_pub)
    results["encap_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    bob_shared_secret = kyber_decapsulate(variant, bob_priv, ciphertext)
    results["decap_ms"] = (time.perf_counter_ns() - t0) / 1e6

    secrets_match = alice_shared_secret == bob_shared_secret
    results["secrets_match"] = secrets_match

    alice_aes = derive_aes_key(alice_shared_secret, salt)
    bob_aes   = derive_aes_key(bob_shared_secret, salt)
    results["derived_key_bytes"] = len(alice_aes)

    t0 = time.perf_counter_ns()
    nonce, enc_msg, tag = aes_gcm_encrypt(alice_aes, message)
    results["encrypt_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    decrypted = aes_gcm_decrypt(bob_aes, nonce, enc_msg, tag)
    results["decrypt_ms"] = (time.perf_counter_ns() - t0) / 1e6

    results["success"]           = decrypted == message
    results["public_key_bytes"]  = len(bob_pub)
    results["private_key_bytes"] = len(bob_priv)
    results["ciphertext_bytes"]  = len(ciphertext)
    results["shared_secret_bytes"] = len(alice_shared_secret)
    results.update(KYBER_SECURITY_INFO[variant])

    return results


def get_kyber_sizes(variant="Kyber768"):
    pub, priv, _ = generate_kyber_keypair(variant)
    ct, ss = kyber_encapsulate(variant, pub)
    return {
        "variant": variant,
        "public_key_bytes":    len(pub),
        "private_key_bytes":   len(priv),
        "ciphertext_bytes":    len(ct),
        "shared_secret_bytes": len(ss),
    }


def run_kyber(variant="Kyber768", iterations=100):
    message = os.urandom(256)
    totals = {k: 0.0 for k in ["keygen_ms", "encap_ms", "decap_ms", "encrypt_ms", "decrypt_ms"]}

    for _ in range(iterations):
        r = simulate_kyber_handshake(variant, message)
        for k in totals:
            totals[k] += r[k]

    averages = {k: v / iterations for k, v in totals.items()}
    averages["variant"] = variant

    r = simulate_kyber_handshake(variant, message)
    for key in ["public_key_bytes", "private_key_bytes", "ciphertext_bytes",
                "shared_secret_bytes", "nist_level", "classical_equiv"]:
        averages[key] = r[key]

    return averages


if __name__ == "__main__":
    print("=" * 65)
    print("     CRYSTALS-KYBER POST-QUANTUM KEM DEMO (FIPS 203 / ML-KEM)")
    print("=" * 65)

    test_message = b"Post-quantum secure message via Kyber KEM + AES-GCM."

    for variant in ["Kyber512", "Kyber768", "Kyber1024"]:
        info = KYBER_SECURITY_INFO[variant]
        print(f"\n🔒 {variant}  [NIST Level {info['nist_level']} — {info['classical_equiv']} equivalent]")
        print("-" * 55)

        result = simulate_kyber_handshake(variant, test_message)

        print(f"  Key Generation       : {result['keygen_ms']:.4f} ms")
        print(f"  Encapsulation        : {result['encap_ms']:.4f} ms  (sender)")
        print(f"  Decapsulation        : {result['decap_ms']:.4f} ms  (receiver)")
        print(f"  AES-GCM Encrypt      : {result['encrypt_ms']:.4f} ms")
        print(f"  AES-GCM Decrypt      : {result['decrypt_ms']:.4f} ms")
        print(f"  Public Key Size      : {result['public_key_bytes']} bytes  ← sent over wire")
        print(f"  Private Key Size     : {result['private_key_bytes']} bytes")
        print(f"  KEM Ciphertext Size  : {result['ciphertext_bytes']} bytes  ← sent over wire")
        print(f"  Shared Secret Size   : {result['shared_secret_bytes']} bytes")
        print(f"  Secrets Match        : {result['secrets_match']}")
        print(f"  Decryption Success   : {result['success']}")

    print("\n📊 Public Key Size: Kyber vs ECDH (what travels over the network)")
    print("-" * 60)
    print(f"  {'Algorithm':<22} {'Public Key (bytes)':<22} {'Ciphertext/Share (bytes)'}")
    print(f"  {'─'*20:<22} {'─'*20:<22} {'─'*22}")
    comparisons = [
        ("ECDH P-256",    65,    32),
        ("ECDH P-384",    97,    48),
        ("ECDH P-521",    133,   66),
        ("Kyber-512",     800,   768),
        ("Kyber-768",     1184,  1088),
        ("Kyber-1024",    1568,  1568),
    ]
    for name, pk, ct in comparisons:
        marker = " ✓ PQ-safe" if "Kyber" in name else " ✗ broken by Shor's"
        print(f"  {name:<22} {pk:<22} {ct:<22}{marker}")

    print("\n  ℹ️  Kyber keys are larger but operations remain fast.")
    print("  ℹ️  This bandwidth cost is the trade-off for quantum resistance.")

    print("\n🧪 Available Kyber/ML-KEM variants in your liboqs install:")
    enabled = oqs.get_enabled_kem_mechanisms()
    kyber_algs = [a for a in enabled if "Kyber" in a or "ML-KEM" in a]
    for alg in kyber_algs:
        print(f"   • {alg}")

    print("\n✅ Kyber KEM demo complete.\n")
