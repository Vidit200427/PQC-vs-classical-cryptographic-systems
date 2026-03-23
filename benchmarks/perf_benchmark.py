import sys
import os
import time
import statistics
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
import seaborn as sns

from classical.rsa_demo    import run_rsa
from classical.ecdsa_demo  import run_ecdsa
from classical.ecdh_demo   import run_ecdh
from post_quantum.kyber_kem      import run_kyber
from post_quantum.dilithium_sign import run_dilithium

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("⚠️  liboqs-python not found. Post-quantum benchmarks will be skipped.")

RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

COLOR_CLASSICAL = "#E74C3C"
COLOR_PQ        = "#2ECC71"
COLOR_NEUTRAL   = "#3498DB"

BENCHMARK_SUITE = [
    {
        "name":     "ECDH P-256",
        "category": "Key Exchange",
        "type":     "classical",
        "fn":       lambda: run_ecdh("P-256", iterations=50),
        "ops":      ["keygen_ms", "exchange_ms", "encrypt_ms", "decrypt_ms"],
    },
    {
        "name":     "ECDH P-384",
        "category": "Key Exchange",
        "type":     "classical",
        "fn":       lambda: run_ecdh("P-384", iterations=50),
        "ops":      ["keygen_ms", "exchange_ms", "encrypt_ms", "decrypt_ms"],
    },
    {
        "name":     "Kyber-512",
        "category": "Key Exchange",
        "type":     "post_quantum",
        "fn":       lambda: run_kyber("Kyber512", iterations=50),
        "ops":      ["keygen_ms", "encap_ms", "decap_ms", "encrypt_ms", "decrypt_ms"],
    },
    {
        "name":     "Kyber-768",
        "category": "Key Exchange",
        "type":     "post_quantum",
        "fn":       lambda: run_kyber("Kyber768", iterations=50),
        "ops":      ["keygen_ms", "encap_ms", "decap_ms", "encrypt_ms", "decrypt_ms"],
    },
    {
        "name":     "Kyber-1024",
        "category": "Key Exchange",
        "type":     "post_quantum",
        "fn":       lambda: run_kyber("Kyber1024", iterations=50),
        "ops":      ["keygen_ms", "encap_ms", "decap_ms", "encrypt_ms", "decrypt_ms"],
    },
    {
        "name":     "RSA-2048",
        "category": "Signature",
        "type":     "classical",
        "fn":       lambda: run_rsa(2048, iterations=20),
        "ops":      ["keygen_ms", "sign_ms", "verify_ms"],
    },
    {
        "name":     "RSA-4096",
        "category": "Signature",
        "type":     "classical",
        "fn":       lambda: run_rsa(4096, iterations=10),
        "ops":      ["keygen_ms", "sign_ms", "verify_ms"],
    },
    {
        "name":     "ECDSA P-256",
        "category": "Signature",
        "type":     "classical",
        "fn":       lambda: run_ecdsa("P-256", iterations=100),
        "ops":      ["keygen_ms", "sign_ms", "verify_ms"],
    },
    {
        "name":     "ECDSA P-384",
        "category": "Signature",
        "type":     "classical",
        "fn":       lambda: run_ecdsa("P-384", iterations=100),
        "ops":      ["keygen_ms", "sign_ms", "verify_ms"],
    },
    {
        "name":     "Dilithium2",
        "category": "Signature",
        "type":     "post_quantum",
        "fn":       lambda: run_dilithium("ML-DSA-44", iterations=100),
        "ops":      ["keygen_ms", "sign_ms", "verify_ms"],
    },
    {
        "name":     "Dilithium3",
        "category": "Signature",
        "type":     "post_quantum",
        "fn":       lambda: run_dilithium("ML-DSA-65", iterations=100),
        "ops":      ["keygen_ms", "sign_ms", "verify_ms"],
    },
    {
        "name":     "Dilithium5",
        "category": "Signature",
        "type":     "post_quantum",
        "fn":       lambda: run_dilithium("ML-DSA-87", iterations=100),
        "ops":      ["keygen_ms", "sign_ms", "verify_ms"],
    },
]


def run_timed_benchmark(fn, warmup=2, trials=5):
    for _ in range(warmup):
        fn()

    trial_results = [fn() for _ in range(trials)]
    ms_keys = [k for k in trial_results[0] if k.endswith("_ms")]
    stats = {}
    for key in ms_keys:
        vals = [r[key] for r in trial_results if key in r]
        stats[key] = {
            "mean": statistics.mean(vals),
            "std":  statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "min":  min(vals),
            "max":  max(vals),
        }

    meta = {k: v for k, v in trial_results[-1].items() if not k.endswith("_ms")}
    stats["_meta"] = meta
    return stats


def run_all_benchmarks(verbose=True):
    all_results = []
    total = len(BENCHMARK_SUITE)

    print("\n" + "═" * 65)
    print("   CLASSICAL vs POST-QUANTUM — PERFORMANCE BENCHMARK SUITE")
    print("═" * 65)

    for i, bench in enumerate(BENCHMARK_SUITE, 1):
        tag = "🔴 Classical" if bench["type"] == "classical" else "🟢 Post-Quantum"
        print(f"\n[{i:02d}/{total}] {tag} — {bench['name']}  ({bench['category']})")

        if bench["type"] == "post_quantum" and not OQS_AVAILABLE:
            print("  ⚠️  Skipped — liboqs not available")
            continue

        try:
            t_start = time.time()
            stats = run_timed_benchmark(bench["fn"])
            elapsed = time.time() - t_start

            row = {
                "name":     bench["name"],
                "category": bench["category"],
                "type":     bench["type"],
            }

            for metric, s in stats.items():
                if metric == "_meta":
                    continue
                row[f"{metric}_mean"] = round(s["mean"], 4)
                row[f"{metric}_std"]  = round(s["std"],  4)
                row[f"{metric}_min"]  = round(s["min"],  4)
                row[f"{metric}_max"]  = round(s["max"],  4)

            row.update(stats.get("_meta", {}))
            all_results.append(row)

            for metric, s in stats.items():
                if metric == "_meta":
                    continue
                label = metric.replace("_ms", "").replace("_", " ").title()
                print(f"  {label:<22}: {s['mean']:>8.4f} ms  ± {s['std']:.4f} ms")
            print(f"  {'Benchmark wall time':<22}: {elapsed:.1f}s")

        except Exception as e:
            print(f"  ❌ Error: {e}")

    return all_results


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


def plot_keygen_comparison(results, output_path):
    df = pd.DataFrame(results)
    df = df[df["keygen_ms_mean"].notna()].copy()
    df = df.sort_values("keygen_ms_mean", ascending=True)
    colors = [COLOR_CLASSICAL if t == "classical" else COLOR_PQ for t in df["type"]]

    fig, ax = plt.subplots(figsize=(14, 6))
    bars = ax.barh(df["name"], df["keygen_ms_mean"], color=colors,
                   xerr=df["keygen_ms_std"], capsize=4, edgecolor="white", linewidth=0.5)
    ax.set_xlabel("Key Generation Time (ms) — lower is better", fontsize=12)
    ax.set_title("Key Generation Performance: Classical vs Post-Quantum",
                 fontsize=14, fontweight="bold", pad=15)

    for bar, val in zip(bars, df["keygen_ms_mean"]):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                f"{val:.3f} ms", va="center", fontsize=9)

    patches = [
        mpatches.Patch(color=COLOR_CLASSICAL, label="Classical (vulnerable to quantum)"),
        mpatches.Patch(color=COLOR_PQ,        label="Post-Quantum (quantum-resistant)"),
    ]
    ax.legend(handles=patches, loc="lower right", fontsize=10)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 Key gen chart saved → {output_path}")


def plot_sign_verify(results, output_path):
    df = pd.DataFrame(results)
    sig_df = df[df["category"] == "Signature"].copy()
    sig_df = sig_df.dropna(subset=["sign_ms_mean", "verify_ms_mean"])

    if sig_df.empty:
        print("⚠️  No signature data to plot.")
        return

    x     = np.arange(len(sig_df))
    width = 0.35

    fig, ax = plt.subplots(figsize=(14, 6))
    bars1 = ax.bar(x - width / 2, sig_df["sign_ms_mean"],   width,
                   label="Sign",   color="#E74C3C", alpha=0.85, edgecolor="white")
    bars2 = ax.bar(x + width / 2, sig_df["verify_ms_mean"], width,
                   label="Verify", color="#2980B9", alpha=0.85, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(sig_df["name"], rotation=30, ha="right", fontsize=10)
    for tick, t in zip(ax.get_xticklabels(), sig_df["type"]):
        tick.set_color(COLOR_CLASSICAL if t == "classical" else COLOR_PQ)

    ax.set_ylabel("Time (ms) — lower is better", fontsize=12)
    ax.set_title("Sign & Verify Performance: Classical vs Post-Quantum Signatures",
                 fontsize=14, fontweight="bold", pad=15)
    ax.legend(fontsize=11)

    for bar in bars1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 0.001,
                f"{h:.3f}", ha="center", va="bottom", fontsize=8)
    for bar in bars2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, h + 0.001,
                f"{h:.3f}", ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 Sign/Verify chart saved → {output_path}")


def plot_heatmap(results, output_path):
    df = pd.DataFrame(results)
    df = df.set_index("name")

    time_cols = [c for c in df.columns if c.endswith("_mean") and "ms" in c]
    heat_df = df[time_cols].copy()
    heat_df.columns = [c.replace("_ms_mean", "").replace("_", " ").title()
                       for c in heat_df.columns]
    heat_norm = heat_df.div(heat_df.max(axis=0))

    fig, ax = plt.subplots(figsize=(12, 8))
    sns.heatmap(
        heat_norm,
        annot=heat_df.round(3),
        fmt=".3f",
        cmap="RdYlGn_r",
        linewidths=0.5,
        ax=ax,
        cbar_kws={"label": "Normalized Time (0=fastest, 1=slowest)"},
    )
    ax.set_title("Operation Time Heatmap — Classical vs Post-Quantum\n"
                 "(values in ms, color = normalized rank)",
                 fontsize=13, fontweight="bold", pad=15)
    ax.set_ylabel("")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 Heatmap saved → {output_path}")


def plot_kem_comparison(results, output_path):
    df = pd.DataFrame(results)
    kem_df = df[df["category"] == "Key Exchange"].copy()
    kem_df["exchange_time"] = kem_df.get("exchange_ms_mean",
                              kem_df.get("encap_ms_mean", None))
    kem_df = kem_df.dropna(subset=["exchange_time"])
    kem_df = kem_df.sort_values("exchange_time")
    colors = [COLOR_CLASSICAL if t == "classical" else COLOR_PQ for t in kem_df["type"]]

    fig, ax = plt.subplots(figsize=(12, 5))
    bars = ax.barh(kem_df["name"], kem_df["exchange_time"],
                   color=colors, edgecolor="white", linewidth=0.5)
    ax.set_xlabel("Exchange / Encapsulation Time (ms) — lower is better", fontsize=12)
    ax.set_title("Key Exchange Performance: ECDH vs Kyber KEM",
                 fontsize=14, fontweight="bold", pad=15)

    for bar, val in zip(bars, kem_df["exchange_time"]):
        ax.text(bar.get_width() + 0.001, bar.get_y() + bar.get_height() / 2,
                f"{val:.4f} ms", va="center", fontsize=9)

    patches = [
        mpatches.Patch(color=COLOR_CLASSICAL, label="ECDH Classical (broken by Shor's)"),
        mpatches.Patch(color=COLOR_PQ,        label="Kyber PQ-KEM (quantum-resistant)"),
    ]
    ax.legend(handles=patches, fontsize=10)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"📊 KEM comparison chart saved → {output_path}")


def print_summary_table(results):
    print("\n" + "═" * 90)
    print("  PERFORMANCE SUMMARY TABLE  (all times in milliseconds, averaged over multiple trials)")
    print("═" * 90)
    print(f"  {'Algorithm':<22} {'Type':<14} {'KeyGen':>9} {'Sign/Encap':>12} {'Verify/Decap':>14}")
    print(f"  {'─'*20:<22} {'─'*12:<14} {'─'*7:>9} {'─'*10:>12} {'─'*12:>14}")

    for r in results:
        name      = r["name"]
        rtype     = r["type"]
        keygen    = r.get("keygen_ms_mean", 0.0)
        sign_val  = r.get("sign_ms_mean") or r.get("encap_ms_mean") or 0.0
        verify_val = r.get("verify_ms_mean") or r.get("decap_ms_mean") or \
                     r.get("exchange_ms_mean") or 0.0
        tag = "🔴 classical" if rtype == "classical" else "🟢 post-qnt"
        print(f"  {name:<22} {tag:<14} {keygen:>9.4f} {sign_val:>12.4f} {verify_val:>14.4f}")

    print("═" * 90)
    print("  🔴 = vulnerable to Shor's Algorithm on quantum hardware")
    print("  🟢 = resistant to known quantum attacks (NIST PQC standardized)")
    print("═" * 90)


if __name__ == "__main__":
    print("\n🚀 Starting full benchmark suite...")
    print("   This may take a few minutes depending on your hardware.\n")

    results = run_all_benchmarks(verbose=True)

    if not results:
        print("❌ No benchmark results collected. Check your environment.")
        sys.exit(1)

    print_summary_table(results)

    csv_path = os.path.join(RESULTS_DIR, "perf_results.csv")
    save_csv(results, csv_path)

    print("\n🎨 Generating charts...")
    plot_keygen_comparison(results, os.path.join(RESULTS_DIR, "keygen_comparison.png"))
    plot_sign_verify(results,       os.path.join(RESULTS_DIR, "sign_verify_comparison.png"))
    plot_kem_comparison(results,    os.path.join(RESULTS_DIR, "kem_comparison.png"))
    plot_heatmap(results,           os.path.join(RESULTS_DIR, "perf_heatmap.png"))

    print("\n✅ Benchmark complete. All outputs saved to benchmarks/results/")
