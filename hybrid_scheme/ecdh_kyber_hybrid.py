import os
import time
import struct

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("⚠️  liboqs-python not found.")


EC_CURVES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}

HYBRID_CONFIGS = {
    "P256+Kyber512":  {"ec": "P-256", "kem": "Kyber512",  "nist_level": 1},
    "P256+Kyber768":  {"ec": "P-256", "kem": "Kyber768",  "nist_level": 3},
    "P384+Kyber768":  {"ec": "P-384", "kem": "Kyber768",  "nist_level": 3},
    "P384+Kyber1024": {"ec": "P-384", "kem": "Kyber1024", "nist_level": 5},
    "P521+Kyber1024": {"ec": "P-521", "kem": "Kyber1024", "nist_level": 5},
}


class HybridKeyPair:
    def __init__(self, ec_curve="P-256", kem_variant="Kyber768"):
        self.ec_curve    = ec_curve
        self.kem_variant = kem_variant

        self.ec_private = ec.generate_private_key(EC_CURVES[ec_curve], backend=default_backend())
        self.ec_public  = self.ec_private.public_key()

        if OQS_AVAILABLE:
            kem = oqs.KeyEncapsulation(kem_variant)
            self.kem_public  = kem.generate_keypair()
            self.kem_private = kem.export_secret_key()
        else:
            self.kem_public  = None
            self.kem_private = None

    def export_public_bundle(self):
        ec_pub_bytes = self.ec_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "ec_public_key":  ec_pub_bytes,
            "kem_public_key": self.kem_public,
            "ec_curve":       self.ec_curve,
            "kem_variant":    self.kem_variant,
        }

    def get_sizes(self):
        ec_pub = len(self.ec_public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        ec_priv = len(self.ec_private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
        return {
            "ec_public_key_bytes":   ec_pub,
            "ec_private_key_bytes":  ec_priv,
            "kem_public_key_bytes":  len(self.kem_public)  if self.kem_public  else 0,
            "kem_private_key_bytes": len(self.kem_private) if self.kem_private else 0,
            "total_public_bytes":    ec_pub + (len(self.kem_public) if self.kem_public else 0),
        }


def kem_combiner(shared_classical, shared_pq, ciphertext_ec, ciphertext_kem,
                 info=b"hybrid-ecdh-kyber-v1"):
    def length_prefix(data):
        return struct.pack(">H", len(data)) + data

    combined_ikm = (
        length_prefix(shared_classical) +
        length_prefix(shared_pq) +
        length_prefix(ciphertext_ec) +
        length_prefix(ciphertext_kem)
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(combined_ikm)


def aes_gcm_encrypt(key, plaintext, aad=b""):
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    enc = cipher.encryptor()
    if aad:
        enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    return nonce, ct, enc.tag


def aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b""):
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    dec = cipher.decryptor()
    if aad:
        dec.authenticate_additional_data(aad)
    return dec.update(ciphertext) + dec.finalize()


def hybrid_handshake_sender(bob_public_bundle):
    ec_curve    = bob_public_bundle["ec_curve"]
    kem_variant = bob_public_bundle["kem_variant"]

    alice_ec_priv = ec.generate_private_key(EC_CURVES[ec_curve], default_backend())
    alice_ec_pub  = alice_ec_priv.public_key()

    bob_ec_pub = serialization.load_der_public_key(
        bob_public_bundle["ec_public_key"], backend=default_backend()
    )
    shared_classical = alice_ec_priv.exchange(ec.ECDH(), bob_ec_pub)

    alice_ec_pub_bytes = alice_ec_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if not OQS_AVAILABLE or bob_public_bundle["kem_public_key"] is None:
        raise RuntimeError("liboqs not available — cannot perform PQ component")

    with oqs.KeyEncapsulation(kem_variant) as kem:
        kyber_ciphertext, shared_pq = kem.encap_secret(bob_public_bundle["kem_public_key"])

    master_secret = kem_combiner(
        shared_classical=shared_classical,
        shared_pq=shared_pq,
        ciphertext_ec=alice_ec_pub_bytes,
        ciphertext_kem=kyber_ciphertext,
    )

    return alice_ec_pub_bytes, kyber_ciphertext, master_secret


def hybrid_handshake_receiver(bob_keypair, alice_ec_pub_bytes, kyber_ciphertext):
    alice_ec_pub = serialization.load_der_public_key(
        alice_ec_pub_bytes, backend=default_backend()
    )
    shared_classical = bob_keypair.ec_private.exchange(ec.ECDH(), alice_ec_pub)

    with oqs.KeyEncapsulation(bob_keypair.kem_variant,
                              secret_key=bob_keypair.kem_private) as kem:
        shared_pq = kem.decap_secret(kyber_ciphertext)

    master_secret = kem_combiner(
        shared_classical=shared_classical,
        shared_pq=shared_pq,
        ciphertext_ec=alice_ec_pub_bytes,
        ciphertext_kem=kyber_ciphertext,
    )

    return master_secret


def simulate_hybrid_session(config_name="P256+Kyber768", message=None):
    if message is None:
        message = os.urandom(1024)

    config      = HYBRID_CONFIGS[config_name]
    ec_curve    = config["ec"]
    kem_variant = config["kem"]

    results = {
        "config":             config_name,
        "ec_curve":           ec_curve,
        "kem_variant":        kem_variant,
        "nist_level":         config["nist_level"],
        "message_size_bytes": len(message),
    }

    t0 = time.perf_counter_ns()
    bob = HybridKeyPair(ec_curve, kem_variant)
    results["keygen_ms"] = (time.perf_counter_ns() - t0) / 1e6

    bob_bundle = bob.export_public_bundle()
    sizes = bob.get_sizes()
    results.update(sizes)

    t0 = time.perf_counter_ns()
    alice_ec_pub, kyber_ct, alice_master = hybrid_handshake_sender(bob_bundle)
    results["sender_handshake_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    bob_master = hybrid_handshake_receiver(bob, alice_ec_pub, kyber_ct)
    results["receiver_handshake_ms"] = (time.perf_counter_ns() - t0) / 1e6

    results["secrets_match"] = (alice_master == bob_master)

    aad = b"hybrid-session-v1"
    t0 = time.perf_counter_ns()
    nonce, ciphertext, tag = aes_gcm_encrypt(alice_master, message, aad)
    results["encrypt_ms"] = (time.perf_counter_ns() - t0) / 1e6

    t0 = time.perf_counter_ns()
    decrypted = aes_gcm_decrypt(bob_master, nonce, ciphertext, tag, aad)
    results["decrypt_ms"] = (time.perf_counter_ns() - t0) / 1e6

    results["decryption_success"]  = (decrypted == message)
    results["kyber_ct_bytes"]      = len(kyber_ct)
    results["ec_ephemeral_bytes"]  = len(alice_ec_pub)
    results["total_wire_bytes"]    = len(alice_ec_pub) + len(kyber_ct)
    results["ciphertext_bytes"]    = len(ciphertext)
    results["total_handshake_ms"]  = (
        results["keygen_ms"] +
        results["sender_handshake_ms"] +
        results["receiver_handshake_ms"]
    )

    return results


def run_hybrid(config_name="P256+Kyber768", iterations=50):
    message = os.urandom(256)
    totals = {k: 0.0 for k in [
        "keygen_ms", "sender_handshake_ms", "receiver_handshake_ms",
        "encrypt_ms", "decrypt_ms", "total_handshake_ms"
    ]}

    for _ in range(iterations):
        r = simulate_hybrid_session(config_name, message)
        for k in totals:
            totals[k] += r[k]

    averages = {k: v / iterations for k, v in totals.items()}
    averages["config"] = config_name

    r = simulate_hybrid_session(config_name, message)
    for key in ["total_wire_bytes", "ec_ephemeral_bytes", "kyber_ct_bytes",
                "ec_public_key_bytes", "kem_public_key_bytes",
                "total_public_bytes", "nist_level"]:
        averages[key] = r.get(key, 0)

    return averages


def migration_cost_analysis():
    print("\n📊 Migration Cost Analysis: Classical → Hybrid → Post-Quantum Only")
    print("=" * 70)

    import sys
    import os
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
    from classical.ecdh_demo import simulate_ecdh_handshake

    classical_r  = simulate_ecdh_handshake("P-256")
    classical_hs = classical_r["keygen_ms"] + classical_r["exchange_ms"]

    print(f"\n  Baseline (ECDH P-256 only):")
    print(f"    Handshake time  : {classical_hs:.4f} ms")
    print(f"    Wire bytes      : {classical_r['public_key_bytes']} bytes  ← sent over wire")

    overhead = {}
    for config_name in ["P256+Kyber512", "P256+Kyber768", "P384+Kyber1024"]:
        if not OQS_AVAILABLE:
            break
        r = simulate_hybrid_session(config_name)
        overhead[config_name] = {
            "extra_time_ms":    r["total_handshake_ms"] - classical_hs,
            "extra_wire_bytes": r["total_wire_bytes"] - classical_r["public_key_bytes"],
            "overhead_pct":     ((r["total_handshake_ms"] / classical_hs) - 1) * 100,
        }

        print(f"\n  {config_name}:")
        print(f"    Handshake time  : {r['total_handshake_ms']:.4f} ms")
        print(f"    Wire bytes      : {r['total_wire_bytes']} bytes")
        print(f"    Extra latency   : +{overhead[config_name]['extra_time_ms']:.4f} ms "
              f"({overhead[config_name]['overhead_pct']:.1f}% overhead)")
        print(f"    Extra bandwidth : +{overhead[config_name]['extra_wire_bytes']} bytes")
        print(f"    NIST Level      : {HYBRID_CONFIGS[config_name]['nist_level']}")

    print(f"""
  Conclusion:
  ──────────────────────────────────────────────────────────────
  The hybrid scheme adds modest overhead (~1–5ms extra latency,
  ~1–2KB extra bandwidth per handshake) while providing FULL
  quantum resistance in addition to classical security.

  This is the approach used by:
    • Google Chrome (X25519Kyber768)
    • Cloudflare TLS 1.3 hybrid
    • Apple iMessage (PQ3 — Kyber + classical)
    • Signal Protocol (PQXDH)

  The small overhead is acceptable for the security guarantee.
  ──────────────────────────────────────────────────────────────
""")
    return overhead


if __name__ == "__main__":
    print("=" * 70)
    print("   HYBRID ECDH + KYBER ENCRYPTION SCHEME")
    print("   (Mirrors Google/Cloudflare TLS 1.3 Hybrid Production Deploy)")
    print("=" * 70)

    if not OQS_AVAILABLE:
        print("\n❌ liboqs-python is required for this demo.")
        exit(1)

    test_message = (
        b"This message is protected by BOTH classical ECDH and post-quantum "
        b"Kyber KEM. Even if a quantum computer breaks ECDH tomorrow, Kyber "
        b"ensures this message remains confidential. This is hybrid security."
    )

    for config_name in HYBRID_CONFIGS:
        config = HYBRID_CONFIGS[config_name]
        print(f"\n🔐 Hybrid Config: {config_name}  [NIST Level {config['nist_level']}]")
        print(f"   Components: {config['ec']} (classical) + {config['kem']} (post-quantum)")
        print("-" * 60)

        try:
            r = simulate_hybrid_session(config_name, test_message)
            print(f"  Key Generation         : {r['keygen_ms']:.4f} ms")
            print(f"  Sender Handshake       : {r['sender_handshake_ms']:.4f} ms  (Alice)")
            print(f"  Receiver Handshake     : {r['receiver_handshake_ms']:.4f} ms  (Bob)")
            print(f"  Total Handshake        : {r['total_handshake_ms']:.4f} ms")
            print(f"  AES-GCM Encrypt        : {r['encrypt_ms']:.4f} ms")
            print(f"  AES-GCM Decrypt        : {r['decrypt_ms']:.4f} ms")
            print(f"  EC Public Key          : {r['ec_public_key_bytes']} bytes")
            print(f"  Kyber Public Key       : {r['kem_public_key_bytes']} bytes")
            print(f"  Total Public Bundle    : {r['total_public_bytes']} bytes  ← Bob sends this")
            print(f"  EC Ephemeral Key       : {r['ec_ephemeral_bytes']} bytes  ← Alice sends")
            print(f"  Kyber Ciphertext       : {r['kyber_ct_bytes']} bytes    ← Alice sends")
            print(f"  Total Wire (Alice→Bob) : {r['total_wire_bytes']} bytes")
            print(f"  Master Secrets Match   : {r['secrets_match']}")
            print(f"  Decryption Success     : {r['decryption_success']}")
        except Exception as e:
            print(f"  ⚠️  Error: {e}")

    migration_cost_analysis()

    print("\n📡 What Travels Over The Wire (per handshake)")
    print("=" * 65)
    print(f"  {'Config':<24} {'Bob→Alice':>12} {'Alice→Bob':>12} {'Total':>10}  {'Level'}")
    print(f"  {'─'*22:<24} {'─'*10:>12} {'─'*10:>12} {'─'*8:>10}  {'─'*5}")
    print(f"  {'ECDH P-256 (pure)':<24} {'91 B':>12} {'91 B':>12} {'182 B':>10}  N/A")

    for config_name in HYBRID_CONFIGS:
        try:
            r = simulate_hybrid_session(config_name)
            bob_to_alice = r["total_public_bytes"]
            alice_to_bob = r["total_wire_bytes"]
            total        = bob_to_alice + alice_to_bob
            level        = HYBRID_CONFIGS[config_name]["nist_level"]
            print(f"  {config_name:<24} {str(bob_to_alice)+' B':>12} "
                  f"{str(alice_to_bob)+' B':>12} {str(total)+' B':>10}  {level}")
        except Exception:
            pass

    print("\n🛡️  Security Guarantee of the Hybrid Scheme")
    print("-" * 55)
    print("""
  master_secret = HKDF(shared_classical ‖ shared_pq ‖ ...)

  This scheme is secure IF:
    ✅ ECDH is secure AND Kyber is secure  → obviously safe
    ✅ ECDH is broken (by Shor's)          → Kyber still protects
    ✅ Kyber has a flaw discovered          → ECDH still protects
    ❌ BOTH are broken simultaneously      → only then is it unsafe
  """)

    print("✅ Hybrid scheme demo complete.\n")
