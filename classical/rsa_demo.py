import time
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def rsa_encrypt(public_key, plaintext):
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_sign(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def get_key_sizes(private_key, public_key):
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {
        "private_key_bytes": len(priv_bytes),
        "public_key_bytes": len(pub_bytes)
    }


def run_rsa(key_size=2048, iterations=50):
    message = os.urandom(32)
    results = {}

    start = time.perf_counter_ns()
    for _ in range(iterations):
        private_key, public_key = generate_rsa_keypair(key_size)
    results["keygen_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    private_key, public_key = generate_rsa_keypair(key_size)

    start = time.perf_counter_ns()
    for _ in range(iterations):
        ciphertext = rsa_encrypt(public_key, message)
    results["encrypt_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    ciphertext = rsa_encrypt(public_key, message)
    start = time.perf_counter_ns()
    for _ in range(iterations):
        rsa_decrypt(private_key, ciphertext)
    results["decrypt_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    start = time.perf_counter_ns()
    for _ in range(iterations):
        signature = rsa_sign(private_key, message)
    results["sign_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    signature = rsa_sign(private_key, message)
    start = time.perf_counter_ns()
    for _ in range(iterations):
        rsa_verify(public_key, message, signature)
    results["verify_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    sizes = get_key_sizes(private_key, public_key)
    results["ciphertext_bytes"] = len(ciphertext)
    results["signature_bytes"] = len(signature)
    results.update(sizes)
    results["key_size_bits"] = key_size

    return results


if __name__ == "__main__":
    print("=" * 55)
    print("        RSA CLASSICAL CRYPTOGRAPHY DEMO")
    print("=" * 55)

    for bits in [2048, 4096]:
        print(f"\n🔑 RSA-{bits}")
        print("-" * 40)

        t0 = time.perf_counter_ns()
        priv, pub = generate_rsa_keypair(bits)
        keygen_ms = (time.perf_counter_ns() - t0) / 1e6
        print(f"  Key Generation   : {keygen_ms:.2f} ms")

        sizes = get_key_sizes(priv, pub)
        print(f"  Public Key Size  : {sizes['public_key_bytes']} bytes")
        print(f"  Private Key Size : {sizes['private_key_bytes']} bytes")

        msg = b"Hello, quantum world! This is RSA."
        ct = rsa_encrypt(pub, msg)
        pt = rsa_decrypt(priv, ct)
        print(f"  Ciphertext Size  : {len(ct)} bytes")
        print(f"  Decryption OK    : {pt == msg}")

        sig = rsa_sign(priv, msg)
        valid = rsa_verify(pub, msg, sig)
        print(f"  Signature Size   : {len(sig)} bytes")
        print(f"  Signature Valid  : {valid}")

        tampered = rsa_verify(pub, b"tampered message", sig)
        print(f"  Tamper Detected  : {not tampered}")

    print("\n✅ RSA demo complete.\n")
