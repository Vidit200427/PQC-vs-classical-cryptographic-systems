import time
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


def generate_ecdsa_keypair(curve_name="P-256"):
    if curve_name not in CURVES:
        raise ValueError(f"Unsupported curve: {curve_name}. Choose from {list(CURVES.keys())}")
    private_key = ec.generate_private_key(curve=CURVES[curve_name], backend=default_backend())
    return private_key, private_key.public_key()


def ecdsa_sign(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(public_key, message, signature):
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def get_key_sizes(private_key, public_key):
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
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


def run_ecdsa(curve_name="P-256", iterations=100):
    message = os.urandom(256)
    results = {"curve": curve_name}

    start = time.perf_counter_ns()
    for _ in range(iterations):
        private_key, public_key = generate_ecdsa_keypair(curve_name)
    results["keygen_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    private_key, public_key = generate_ecdsa_keypair(curve_name)

    start = time.perf_counter_ns()
    for _ in range(iterations):
        signature = ecdsa_sign(private_key, message)
    results["sign_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    signature = ecdsa_sign(private_key, message)
    start = time.perf_counter_ns()
    for _ in range(iterations):
        ecdsa_verify(public_key, message, signature)
    results["verify_ms"] = (time.perf_counter_ns() - start) / 1e6 / iterations

    sizes = get_key_sizes(private_key, public_key)
    results["signature_bytes"] = len(signature)
    results.update(sizes)

    return results


if __name__ == "__main__":
    print("=" * 55)
    print("        ECDSA CLASSICAL CRYPTOGRAPHY DEMO")
    print("=" * 55)

    test_message = b"Authenticating this message with ECDSA."

    for curve_name in ["P-256", "P-384", "P-521"]:
        print(f"\n🔑 ECDSA ({curve_name})")
        print("-" * 40)

        t0 = time.perf_counter_ns()
        priv, pub = generate_ecdsa_keypair(curve_name)
        keygen_ms = (time.perf_counter_ns() - t0) / 1e6
        print(f"  Key Generation   : {keygen_ms:.4f} ms")

        sizes = get_key_sizes(priv, pub)
        print(f"  Public Key Size  : {sizes['public_key_bytes']} bytes")
        print(f"  Private Key Size : {sizes['private_key_bytes']} bytes")

        t0 = time.perf_counter_ns()
        sig = ecdsa_sign(priv, test_message)
        sign_ms = (time.perf_counter_ns() - t0) / 1e6
        print(f"  Signing Time     : {sign_ms:.4f} ms")
        print(f"  Signature Size   : {len(sig)} bytes")

        t0 = time.perf_counter_ns()
        valid = ecdsa_verify(pub, test_message, sig)
        verify_ms = (time.perf_counter_ns() - t0) / 1e6
        print(f"  Verify Time      : {verify_ms:.4f} ms")
        print(f"  Signature Valid  : {valid}")

        tampered = ecdsa_verify(pub, b"tampered message", sig)
        print(f"  Tamper Detected  : {not tampered}")

        bad_sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
        bad_sig_detected = ecdsa_verify(pub, test_message, bad_sig)
        print(f"  Bad Sig Detected : {not bad_sig_detected}")

    print("\n📊 ECDSA vs RSA Signature Size Comparison")
    print("-" * 45)
    print(f"  {'Algorithm':<20} {'Sig Size (bytes)':<20}")
    print(f"  {'─'*18:<20} {'─'*16:<20}")
    for curve_name in ["P-256", "P-384", "P-521"]:
        priv, pub = generate_ecdsa_keypair(curve_name)
        sig = ecdsa_sign(priv, test_message)
        print(f"  {f'ECDSA ({curve_name})':<20} {len(sig):<20}")
    print(f"  {'RSA-2048 (PSS)':<20} {'256':<20}  ← for reference")
    print(f"  {'RSA-4096 (PSS)':<20} {'512':<20}  ← for reference")

    print("\n✅ ECDSA demo complete.\n")
