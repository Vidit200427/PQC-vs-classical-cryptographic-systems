import time
import os
import oqs


NTRU_VARIANTS = {
    "NTRU-HPS-2048-509": {"nist_level": 1, "n": 509,  "q": 2048},
    "NTRU-HPS-2048-677": {"nist_level": 3, "n": 677,  "q": 2048},
    "NTRU-HPS-4096-821": {"nist_level": 5, "n": 821,  "q": 4096},
    "NTRU-HRSS-701":     {"nist_level": 3, "n": 701,  "q": 8192},
}


def generate_ntru_keypair(variant="NTRU-HPS-2048-677"):
    enabled = oqs.get_enabled_kem_mechanisms()
    if variant not in enabled:
        raise ValueError(
            f"'{variant}' is not available in your liboqs build.\n"
            f"Available NTRU variants: {[v for v in enabled if 'ntru' in v.lower() or 'NTRU' in v]}"
        )
    kem = oqs.KeyEncapsulation(variant)
    public_key = kem.generate_keypair()
    private_key = kem.export_secret_key()
    return public_key, private_key


def ntru_encapsulate(variant, public_key):
    with oqs.KeyEncapsulation(variant) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def ntru_decapsulate(variant, private_key, ciphertext):
    with oqs.KeyEncapsulation(variant, secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


def simulate_ntru_handshake(variant="NTRU-HPS-2048-677", message=None):
    results = {"variant": variant}

    enabled = oqs.get_enabled_kem_mechanisms()
    if variant not in enabled:
        results["error"] = f"Variant {variant} not available"
        return results

    t0 = time.perf_counter_ns()
    public_key, private_key = generate_ntru_keypair(variant)
    results["keygen_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    ciphertext, alice_secret = ntru_encapsulate(variant, public_key)
    results["encap_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    bob_secret = ntru_decapsulate(variant, private_key, ciphertext)
    results["decap_ms"] = (time.perf_counter_ns() - t0) / 1e6

    results["secrets_match"]        = alice_secret == bob_secret
    results["public_key_bytes"]     = len(public_key)
    results["private_key_bytes"]    = len(private_key)
    results["ciphertext_bytes"]     = len(ciphertext)
    results["shared_secret_bytes"]  = len(alice_secret)

    if variant in NTRU_VARIANTS:
        results.update(NTRU_VARIANTS[variant])

    return results


def get_ntru_sizes(variant="NTRU-HPS-2048-677"):
    enabled = oqs.get_enabled_kem_mechanisms()
    if variant not in enabled:
        return {"variant": variant, "error": "not available"}
    pub, priv = generate_ntru_keypair(variant)
    ct, ss = ntru_encapsulate(variant, pub)
    return {
        "variant":             variant,
        "public_key_bytes":    len(pub),
        "private_key_bytes":   len(priv),
        "ciphertext_bytes":    len(ct),
        "shared_secret_bytes": len(ss),
    }


def run_ntru(variant="NTRU-HPS-2048-677", iterations=100):
    enabled = oqs.get_enabled_kem_mechanisms()
    if variant not in enabled:
        return {"variant": variant, "error": "not available in this build"}

    totals = {k: 0.0 for k in ["keygen_ms", "encap_ms", "decap_ms"]}

    for _ in range(iterations):
        r = simulate_ntru_handshake(variant)
        if "error" in r:
            return r
        for k in totals:
            totals[k] += r[k]

    averages = {k: v / iterations for k, v in totals.items()}
    averages["variant"] = variant

    r = simulate_ntru_handshake(variant)
    for key in ["public_key_bytes", "private_key_bytes", "ciphertext_bytes",
                "shared_secret_bytes", "nist_level"]:
        averages[key] = r.get(key, "N/A")

    return averages


if __name__ == "__main__":
    print("=" * 65)
    print("         NTRU POST-QUANTUM KEM DEMO")
    print("=" * 65)

    enabled = oqs.get_enabled_kem_mechanisms()
    available_ntru = [v for v in NTRU_VARIANTS if v in enabled]

    if not available_ntru:
        print("\n⚠️  No NTRU variants found in your liboqs build.")
        print("   Try: pip install --upgrade liboqs-python")
    else:
        for variant in available_ntru:
            meta = NTRU_VARIANTS[variant]
            print(f"\n🔒 {variant}  [NIST Level {meta['nist_level']} | n={meta['n']}, q={meta['q']}]")
            print("-" * 55)

            result = simulate_ntru_handshake(variant)

            if "error" in result:
                print(f"  ⚠️  Error: {result['error']}")
                continue

            print(f"  Key Generation   : {result['keygen_ms']:.4f} ms")
            print(f"  Encapsulation    : {result['encap_ms']:.4f} ms")
            print(f"  Decapsulation    : {result['decap_ms']:.4f} ms")
            print(f"  Public Key Size  : {result['public_key_bytes']} bytes")
            print(f"  Private Key Size : {result['private_key_bytes']} bytes")
            print(f"  Ciphertext Size  : {result['ciphertext_bytes']} bytes")
            print(f"  Shared Secret    : {result['shared_secret_bytes']} bytes")
            print(f"  Secrets Match    : {result['secrets_match']}")

    print("\n📊 NTRU vs Kyber — Key & Ciphertext Size Comparison")
    print("=" * 65)
    print(f"  {'Algorithm':<28} {'Pub Key':>10}  {'Priv Key':>10}  {'Ciphertext':>12}  {'Level'}")
    print(f"  {'─'*26:<28} {'─'*8:>10}  {'─'*8:>10}  {'─'*10:>12}  {'─'*5}")

    print(f"\n  — Classical (broken by Shor's) —")
    classical = [
        ("ECDH P-256 (classical)", 65,  32, 32,  "N/A"),
        ("ECDH P-384 (classical)", 97,  48, 48,  "N/A"),
    ]
    for name, pk, sk, ct, lvl in classical:
        print(f"  {name:<28} {str(pk)+' B':>10}  {str(sk)+' B':>10}  {str(ct)+' B':>12}  {lvl}")

    print(f"\n  — Post-Quantum —")
    pq_kems = [
        ("Kyber512",        "Kyber512"),
        ("Kyber768",        "Kyber768"),
        ("Kyber1024",       "Kyber1024"),
        ("NTRU-HPS-2048-509", "NTRU-HPS-2048-509"),
        ("NTRU-HPS-2048-677", "NTRU-HPS-2048-677"),
        ("NTRU-HPS-4096-821", "NTRU-HPS-4096-821"),
    ]
    for display, variant in pq_kems:
        if variant not in enabled:
            print(f"  {display:<28} {'(not available)':>36}")
            continue
        try:
            if "NTRU" in variant:
                sizes = get_ntru_sizes(variant)
            else:
                from post_quantum.kyber_kem import simulate_kyber_handshake
                r = simulate_kyber_handshake(variant)
                sizes = {
                    "public_key_bytes":  r["public_key_bytes"],
                    "private_key_bytes": r["private_key_bytes"],
                    "ciphertext_bytes":  r["ciphertext_bytes"],
                }
            lvl = NTRU_VARIANTS.get(variant, {}).get("nist_level", "—")
            pk  = sizes["public_key_bytes"]
            sk  = sizes["private_key_bytes"]
            ct  = sizes["ciphertext_bytes"]
            print(f"  {display:<28} {str(pk)+' B':>10}  {str(sk)+' B':>10}  {str(ct)+' B':>12}  {lvl}")
        except Exception as e:
            print(f"  {display:<28} Error: {e}")

    print("\n💡 Key insight:")
    print("   NTRU has larger public keys than Kyber but comparable ciphertexts.")
    print("   NTRU is older (1996) and more studied; Kyber is the NIST standard.")
    print("   Both are quantum-resistant; Kyber is preferred for new systems.")

    print("\n🧪 All available KEM algorithms in your liboqs build:")
    for k in oqs.get_enabled_kem_mechanisms():
        print(f"   • {k}")

    print("\n✅ NTRU demo complete.\n")
