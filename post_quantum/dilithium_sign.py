import time
import os
import oqs


DILITHIUM_VARIANTS = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
}

EXTENDED_VARIANTS = {
    "Falcon-512":            "Falcon-512",
    "Falcon-1024":           "Falcon-1024",
    "SLH_DSA_PURE_SHA2_128F": "SLH_DSA_PURE_SHA2_128F",
}

SECURITY_INFO = {
    "ML-DSA-44":             {"nist_level": 2, "basis": "MLWE/MSIS", "pq_secure": True},
    "ML-DSA-65":             {"nist_level": 3, "basis": "MLWE/MSIS", "pq_secure": True},
    "ML-DSA-87":             {"nist_level": 5, "basis": "MLWE/MSIS", "pq_secure": True},
    "Falcon-512":            {"nist_level": 1, "basis": "NTRU Lattice", "pq_secure": True},
    "Falcon-1024":           {"nist_level": 5, "basis": "NTRU Lattice", "pq_secure": True},
    "SLH_DSA_PURE_SHA2_128F": {"nist_level": 1, "basis": "Hash-based", "pq_secure": True},
}


def generate_dilithium_keypair(variant="ML-DSA-65"):
    if variant not in DILITHIUM_VARIANTS and variant not in EXTENDED_VARIANTS:
        raise ValueError(f"Unknown variant '{variant}'.")
    signer = oqs.Signature(variant)
    public_key = signer.generate_keypair()
    private_key = signer.export_secret_key()
    return public_key, private_key


def dilithium_sign(variant, private_key, message):
    with oqs.Signature(variant, secret_key=private_key) as signer:
        signature = signer.sign(message)
    return signature


def dilithium_verify(variant, public_key, message, signature):
    with oqs.Signature(variant) as verifier:
        return verifier.verify(message, signature, public_key)


def get_dilithium_sizes(variant="ML-DSA-65"):
    message = os.urandom(256)
    pub, priv = generate_dilithium_keypair(variant)
    sig = dilithium_sign(variant, priv, message)
    return {
        "variant":           variant,
        "public_key_bytes":  len(pub),
        "private_key_bytes": len(priv),
        "signature_bytes":   len(sig),
    }


def simulate_dilithium_signing(variant="ML-DSA-65", message=None):
    if message is None:
        message = os.urandom(1024)

    results = {"variant": variant, "message_size_bytes": len(message)}

    t0 = time.perf_counter_ns()
    public_key, private_key = generate_dilithium_keypair(variant)
    results["keygen_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    signature = dilithium_sign(variant, private_key, message)
    results["sign_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    valid = dilithium_verify(variant, public_key, message, signature)
    results["verify_ms"] = (time.perf_counter_ns() - t0) / 1e6

    results["signature_valid"] = valid

    tampered_msg = bytearray(message)
    tampered_msg[0] ^= 0xFF
    results["tamper_message_detected"] = not dilithium_verify(
        variant, public_key, bytes(tampered_msg), signature
    )

    tampered_sig = bytearray(signature)
    tampered_sig[10] ^= 0xFF
    results["tamper_signature_detected"] = not dilithium_verify(
        variant, public_key, message, bytes(tampered_sig)
    )

    results["public_key_bytes"]  = len(public_key)
    results["private_key_bytes"] = len(private_key)
    results["signature_bytes"]   = len(signature)

    if variant in SECURITY_INFO:
        results.update(SECURITY_INFO[variant])

    return results


def run_dilithium(variant="ML-DSA-65", iterations=100):
    message = os.urandom(256)
    totals = {k: 0.0 for k in ["keygen_ms", "sign_ms", "verify_ms"]}

    for _ in range(iterations):
        r = simulate_dilithium_signing(variant, message)
        for k in totals:
            totals[k] += r[k]

    averages = {k: v / iterations for k, v in totals.items()}
    averages["variant"] = variant

    r = simulate_dilithium_signing(variant, message)
    for key in ["public_key_bytes", "private_key_bytes", "signature_bytes", "nist_level", "basis"]:
        averages[key] = r.get(key, "N/A")

    return averages


def run_extended_signature_comparison(message=None):
    if message is None:
        message = os.urandom(256)

    all_variants = list(DILITHIUM_VARIANTS.keys()) + list(EXTENDED_VARIANTS.keys())
    enabled = oqs.get_enabled_sig_mechanisms()
    results = []

    for variant in all_variants:
        if variant not in enabled:
            print(f"  ⚠️  {variant} not available in this liboqs build — skipping.")
            continue
        try:
            r = simulate_dilithium_signing(variant, message)
            results.append(r)
        except Exception as e:
            print(f"  ❌ {variant} failed: {e}")

    return results


if __name__ == "__main__":
    print("=" * 68)
    print("  CRYSTALS-DILITHIUM POST-QUANTUM SIGNATURE DEMO (FIPS 204 / ML-DSA)")
    print("=" * 68)

    test_message = b"This document is signed with a post-quantum signature scheme."

    for variant in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
        info = SECURITY_INFO[variant]
        print(f"\n✍️  {variant}  [NIST Level {info['nist_level']} — {info['basis']}]")
        print("-" * 55)

        result = simulate_dilithium_signing(variant, test_message)

        print(f"  Key Generation       : {result['keygen_ms']:.4f} ms")
        print(f"  Signing Time         : {result['sign_ms']:.4f} ms")
        print(f"  Verification Time    : {result['verify_ms']:.4f} ms")
        print(f"  Public Key Size      : {result['public_key_bytes']} bytes")
        print(f"  Private Key Size     : {result['private_key_bytes']} bytes")
        print(f"  Signature Size       : {result['signature_bytes']} bytes  ← compare to ECDSA ~72 bytes!")
        print(f"  Signature Valid      : {result['signature_valid']}")
        print(f"  Tampered Msg Caught  : {result['tamper_message_detected']}")
        print(f"  Tampered Sig Caught  : {result['tamper_signature_detected']}")

    print("\n📊 Signature Size Comparison: Classical vs Post-Quantum")
    print("=" * 65)
    print(f"  {'Algorithm':<32} {'Sig Size':>12}  {'PQ-Safe?'}")
    print(f"  {'─'*30:<32} {'─'*8:>12}  {'─'*8}")

    classical_sigs = [
        ("ECDSA P-256",  "~72 bytes",  "❌ No"),
        ("ECDSA P-384",  "~104 bytes", "❌ No"),
        ("RSA-2048 PSS", "256 bytes",  "❌ No"),
        ("RSA-4096 PSS", "512 bytes",  "❌ No"),
    ]
    for name, size, pq in classical_sigs:
        print(f"  {name:<32} {size:>12}  {pq}")

    print()
    enabled = oqs.get_enabled_sig_mechanisms()
    pq_sigs = [
        ("ML-DSA-44",              "ML-DSA-44"),
        ("ML-DSA-65",              "ML-DSA-65"),
        ("ML-DSA-87",              "ML-DSA-87"),
        ("Falcon-512",             "Falcon-512"),
        ("Falcon-1024",            "Falcon-1024"),
        ("SLH_DSA_PURE_SHA2_128F", "SLH_DSA_PURE_SHA2_128F"),
    ]
    for display_name, variant in pq_sigs:
        if variant not in enabled:
            continue
        try:
            sizes = get_dilithium_sizes(variant)
            print(f"  {display_name:<32} {str(sizes['signature_bytes']) + ' bytes':>12}  ✅ Yes")
        except Exception:
            print(f"  {display_name:<32} {'N/A':>12}  ✅ Yes")

    print("\n🧪 All available PQ signature schemes in your liboqs build:")
    all_sigs = oqs.get_enabled_sig_mechanisms()
    for s in all_sigs:
        print(f"   • {s}")

    print("\n✅ Dilithium signature demo complete.\n")
