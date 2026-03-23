import sys
import os
import csv
import warnings
warnings.filterwarnings("ignore")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os as _os

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("⚠️  liboqs-python not available. PQ size data will be skipped.")

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

COLOR_CLASSICAL = "#E74C3C"
COLOR_PQ        = "#2ECC71"


def measure_rsa_sizes(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    msg = _os.urandom(64)
    sig = private_key.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    ct = public_key.encrypt(
        _os.urandom(32),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    return {
        "name":              f"RSA-{key_size}",
        "category":          "Signature + KEM",
        "type":              "classical",
        "public_key_bytes":  len(pub_bytes),
        "private_key_bytes": len(priv_bytes),
        "signature_bytes":   len(sig),
        "ciphertext_bytes":  len(ct),
        "nist_security_level": "N/A",
        "pq_safe":           False,
    }


def measure_ecdsa_sizes(curve_name):
    curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    private_key = ec.generate_private_key(curve=curves[curve_name], backend=default_backend())
    public_key  = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    msg = _os.urandom(64)
    sig = private_key.sign(msg, ec.ECDSA(hashes.SHA256()))

    return {
        "name":              f"ECDSA {curve_name}",
        "category":          "Signature",
        "type":              "classical",
        "public_key_bytes":  len(pub_bytes),
        "private_key_bytes": len(priv_bytes),
        "signature_bytes":   len(sig),
        "ciphertext_bytes":  None,
        "nist_security_level": "N/A",
        "pq_safe":           False,
    }


def measure_ecdh_sizes(curve_name):
    curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}
    private_key = ec.generate_private_key(curve=curves[curve_name], backend=default_backend())
    public_key  = private_key.public_key()

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    peer_priv = ec.generate_private_key(curves[curve_name], default_backend())
    shared = private_key.exchange(ec.ECDH(), peer_priv.public_key())

    return {
        "name":              f"ECDH {curve_name}",
        "category":          "Key Exchange",
        "type":              "classical",
        "public_key_bytes":  len(pub_bytes),
        "private_key_bytes": len(priv_bytes),
        "signature_bytes":   None,
        "ciphertext_bytes":  len(shared),
        "nist_security_level": "N/A",
        "pq_safe":           False,
    }


def measure_pq_kem_sizes(variant, nist_level):
    if not OQS_AVAILABLE:
        return None
    enabled = oqs.get_enabled_kem_mechanisms()
    if variant not in enabled:
        return None

    kem  = oqs.KeyEncapsulation(variant)
    pub  = kem.generate_keypair()
    priv = kem.export_secret_key()

    with oqs.KeyEncapsulation(variant) as enc:
        ct, ss = enc.encap_secret(pub)

    return {
        "name":                variant,
        "category":            "Key Exchange",
        "type":                "post_quantum",
        "public_key_bytes":    len(pub),
        "private_key_bytes":   len(priv),
        "signature_bytes":     None,
        "ciphertext_bytes":    len(ct),
        "shared_secret_bytes": len(ss),
        "nist_security_level": nist_level,
        "pq_safe":             True,
    }


def measure_pq_sig_sizes(variant, nist_level):
    if not OQS_AVAILABLE:
        return None
    enabled = oqs.get_enabled_sig_mechanisms()
    if variant not in enabled:
        return None

    signer = oqs.Signature(variant)
    pub  = signer.generate_keypair()
    priv = signer.export_secret_key()

    msg = _os.urandom(256)
    with oqs.Signature(variant, secret_key=priv) as s:
        sig = s.sign(msg)

    return {
        "name":              variant,
        "category":          "Signature",
        "type":              "post_quantum",
        "public_key_bytes":  len(pub),
        "private_key_bytes": len(priv),
        "signature_bytes":   len(sig),
        "ciphertext_bytes":  None,
        "nist_security_level": nist_level,
        "pq_safe":           True,
    }


def collect_all_sizes():
    results = []

    print("\n" + "═" * 60)
    print("   ARTIFACT SIZE ANALYSIS — CLASSICAL vs POST-QUANTUM")
    print("═" * 60)

    print("\n🔴 Classical Algorithms")
    for bits in [2048, 4096]:
        r = measure_rsa_sizes(bits)
        results.append(r)
        print(f"   RSA-{bits}: pub={r['public_key_bytes']}B  "
              f"priv={r['private_key_bytes']}B  "
              f"sig={r['signature_bytes']}B  "
              f"ct={r['ciphertext_bytes']}B")

    for curve in ["P-256", "P-384", "P-521"]:
        r = measure_ecdsa_sizes(curve)
        results.append(r)
        print(f"   ECDSA {curve}: pub={r['public_key_bytes']}B  "
              f"priv={r['private_key_bytes']}B  "
              f"sig={r['signature_bytes']}B")

    for curve in ["P-256", "P-384", "P-521"]:
        r = measure_ecdh_sizes(curve)
        results.append(r)
        print(f"   ECDH {curve}:  pub={r['public_key_bytes']}B  "
              f"priv={r['private_key_bytes']}B  "
              f"ss={r['ciphertext_bytes']}B")

    if OQS_AVAILABLE:
        print("\n🟢 Post-Quantum KEM Algorithms")
        pq_kems = [
            ("Kyber512",          1),
            ("Kyber768",          3),
            ("Kyber1024",         5),
            ("NTRU-HPS-2048-509", 1),
            ("NTRU-HPS-2048-677", 3),
            ("NTRU-HPS-4096-821", 5),
        ]
        for variant, level in pq_kems:
            r = measure_pq_kem_sizes(variant, level)
            if r:
                results.append(r)
                print(f"   {variant}: pub={r['public_key_bytes']}B  "
                      f"priv={r['private_key_bytes']}B  "
                      f"ct={r['ciphertext_bytes']}B")
            else:
                print(f"   {variant}: ⚠️ not available")

        print("\n🟢 Post-Quantum Signature Algorithms")
        pq_sigs = [
            ("ML-DSA-44",              2),
            ("ML-DSA-65",              3),
            ("ML-DSA-87",              5),
            ("Falcon-512",             1),
            ("Falcon-1024",            5),
            ("SLH_DSA_PURE_SHA2_128F", 1),
            ("SLH_DSA_PURE_SHA2_256F", 5),
        ]
        for variant, level in pq_sigs:
            r = measure_pq_sig_sizes(variant, level)
            if r:
                results.append(r)
                print(f"   {variant}: pub={r['public_key_bytes']}B  "
                      f"priv={r['private_key_bytes']}B  "
                      f"sig={r['signature_bytes']}B")
            else:
                print(f"   {variant}: ⚠️ not available")

    return [r for r in results if r is not None]


def plot_signature_sizes(df, output_path):
    sig_df = df[df["signature_bytes"].notna()].sort_values("signature_bytes")
    colors = [COLOR_CLASSICAL if t == "classical" else COLOR_PQ for t in sig_df["type"]]

    fig, ax = plt.subplots(figsize=(13, 7))
    bars = ax.barh(sig_df["name"], sig_df["signature_bytes"],
                   color=colors, edgecolor="white", linewidth=0.6)

    for bar, val in zip(bars, sig_df["signature_bytes"]):
        ax.text(bar.get_width() + 20, bar.get_y() + bar.get_height() / 2,
                f"{int(val):,} B", va="center", fontsize=9)

    ax.set_xlabel("Signature Size (bytes) — lower is smaller", fontsize=12)
    ax.set_title("Signature Size Comparison: Classical vs Post-Quantum\n"
                 "(PQ signatures are larger — the bandwidth cost of quantum safety)",
                 fontsize=13, fontweight="bold", pad=15)
    patches = [
        mpatches.Patch(color=COLOR_CLASSICAL, label="Classical — broken by Shor's Algorithm"),
        mpatches.Patch(color=COLOR_PQ,        label="Post-Quantum — quantum-resistant"),
    ]
    ax.legend(handles=patches, fontsize=10)
    ax.set_xlim(right=ax.get_xlim()[1] * 1.25)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 Signature sizes chart saved → {output_path}")


def plot_public_key_sizes(df, output_path):
    pk_df = df[df["public_key_bytes"].notna()].sort_values("public_key_bytes")
    colors = [COLOR_CLASSICAL if t == "classical" else COLOR_PQ for t in pk_df["type"]]

    fig, ax = plt.subplots(figsize=(13, 9))
    bars = ax.barh(pk_df["name"], pk_df["public_key_bytes"],
                   color=colors, edgecolor="white", linewidth=0.6)

    for bar, val in zip(bars, pk_df["public_key_bytes"]):
        ax.text(bar.get_width() + 5, bar.get_y() + bar.get_height() / 2,
                f"{int(val):,} B", va="center", fontsize=9)

    ax.set_xlabel("Public Key Size (bytes)", fontsize=12)
    ax.set_title("Public Key Size: Classical vs Post-Quantum\n"
                 "(larger keys = more bandwidth during handshake)",
                 fontsize=13, fontweight="bold", pad=15)
    patches = [
        mpatches.Patch(color=COLOR_CLASSICAL, label="Classical"),
        mpatches.Patch(color=COLOR_PQ,        label="Post-Quantum"),
    ]
    ax.legend(handles=patches, fontsize=10)
    ax.set_xlim(right=ax.get_xlim()[1] * 1.2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 Public key sizes chart saved → {output_path}")


def plot_ciphertext_sizes(df, output_path):
    ct_df = df[df["ciphertext_bytes"].notna()].sort_values("ciphertext_bytes")
    colors = [COLOR_CLASSICAL if t == "classical" else COLOR_PQ for t in ct_df["type"]]

    fig, ax = plt.subplots(figsize=(12, 7))
    bars = ax.barh(ct_df["name"], ct_df["ciphertext_bytes"],
                   color=colors, edgecolor="white")

    for bar, val in zip(bars, ct_df["ciphertext_bytes"]):
        ax.text(bar.get_width() + 5, bar.get_y() + bar.get_height() / 2,
                f"{int(val):,} B", va="center", fontsize=9)

    ax.set_xlabel("Ciphertext / Shared Secret Size (bytes)", fontsize=12)
    ax.set_title("KEM Ciphertext Size: ECDH vs Kyber vs NTRU\n"
                 "(bytes sent over the wire during key exchange)",
                 fontsize=13, fontweight="bold", pad=15)
    patches = [
        mpatches.Patch(color=COLOR_CLASSICAL, label="Classical ECDH (shared secret)"),
        mpatches.Patch(color=COLOR_PQ,        label="Post-Quantum KEM (ciphertext)"),
    ]
    ax.legend(handles=patches, fontsize=10)
    ax.set_xlim(right=ax.get_xlim()[1] * 1.2)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 Ciphertext sizes chart saved → {output_path}")


def plot_overview(df, output_path):
    fig, axes = plt.subplots(2, 2, figsize=(18, 14))
    fig.suptitle("Cryptographic Artifact Size Analysis\nClassical vs Post-Quantum Cryptography",
                 fontsize=16, fontweight="bold", y=1.01)

    def make_hbar(ax, df_col, title):
        sub = df[df[df_col].notna()].sort_values(df_col)
        cols = [COLOR_CLASSICAL if t == "classical" else COLOR_PQ for t in sub["type"]]
        ax.barh(sub["name"], sub[df_col], color=cols, edgecolor="white")
        ax.set_title(title, fontweight="bold")
        ax.set_xlabel("Bytes")

    make_hbar(axes[0, 0], "public_key_bytes",  "Public Key Size (bytes)")
    make_hbar(axes[0, 1], "private_key_bytes", "Private Key Size (bytes)")
    make_hbar(axes[1, 0], "signature_bytes",   "Signature Size (bytes)")
    make_hbar(axes[1, 1], "ciphertext_bytes",  "Ciphertext / Shared Secret (bytes)")

    patches = [
        mpatches.Patch(color=COLOR_CLASSICAL, label="Classical (quantum-vulnerable)"),
        mpatches.Patch(color=COLOR_PQ,        label="Post-Quantum (quantum-resistant)"),
    ]
    fig.legend(handles=patches, loc="lower center", ncol=2,
               fontsize=11, bbox_to_anchor=(0.5, -0.03))

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 Overview panel saved → {output_path}")


def print_size_table(results):
    print("\n" + "═" * 95)
    print("  ARTIFACT SIZE TABLE  (all values in bytes)")
    print("═" * 95)
    print(f"  {'Algorithm':<30} {'Type':<14} {'Pub Key':>10} {'Priv Key':>10}"
          f" {'Signature':>12} {'Ciphertext':>12}  {'PQ Safe'}")
    print(f"  {'─'*28:<30} {'─'*12:<14} {'─'*8:>10} {'─'*8:>10}"
          f" {'─'*10:>12} {'─'*10:>12}  {'─'*7}")

    for r in results:
        pub  = str(r.get("public_key_bytes", "—"))
        priv = str(r.get("private_key_bytes", "—"))
        sig  = str(r.get("signature_bytes") or "—")
        ct   = str(r.get("ciphertext_bytes") or "—")
        safe = "✅ Yes" if r.get("pq_safe") else "❌ No"
        tag  = "🔴 classical" if r["type"] == "classical" else "🟢 post-qnt"
        print(f"  {r['name']:<30} {tag:<14} {pub:>10} {priv:>10} {sig:>12} {ct:>12}  {safe}")

    print("═" * 95)


def save_csv(results, path):
    if not results:
        return
    all_keys = set()
    for r in results:
        all_keys.update(r.keys())
    fieldnames = sorted(all_keys)

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow({k: row.get(k, "") for k in fieldnames})
    print(f"\n💾 CSV saved → {path}")


if __name__ == "__main__":
    print("\n📏 Starting artifact size analysis...")

    results = collect_all_sizes()

    if not results:
        print("❌ No results collected.")
        sys.exit(1)

    df = pd.DataFrame(results)
    df["signature_bytes"]   = pd.to_numeric(df["signature_bytes"],  errors="coerce")
    df["ciphertext_bytes"]  = pd.to_numeric(df["ciphertext_bytes"], errors="coerce")
    df["public_key_bytes"]  = pd.to_numeric(df["public_key_bytes"], errors="coerce")
    df["private_key_bytes"] = pd.to_numeric(df["private_key_bytes"],errors="coerce")

    print_size_table(results)
    save_csv(results, os.path.join(RESULTS_DIR, "size_results.csv"))

    print("\n🎨 Generating size charts...")
    plot_signature_sizes( df, os.path.join(RESULTS_DIR, "signature_sizes.png"))
    plot_public_key_sizes(df, os.path.join(RESULTS_DIR, "key_sizes.png"))
    plot_ciphertext_sizes(df, os.path.join(RESULTS_DIR, "ciphertext_sizes.png"))
    plot_overview(        df, os.path.join(RESULTS_DIR, "size_overview.png"))

    print("\n✅ Size analysis complete. All charts saved to benchmarks/results/")
