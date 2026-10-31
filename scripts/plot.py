#!/usr/bin/env python3
"""Plot Attack 0 impact: CPU% and memory vs counter gap, from measure.py's CSV.

    python3 plot.py --csv ../results/attack0.csv --out ../results/attack0.png

Aggregates samples per gap (mean + peak) and draws two panels. Requires matplotlib
(pip install matplotlib). Falls back to printing a table if matplotlib is missing.
"""
import argparse
import csv
from collections import defaultdict


def load(path):
    by_gap_cpu = defaultdict(list)
    by_gap_mem = defaultdict(list)
    with open(path) as f:
        for row in csv.DictReader(f):
            g = int(row["gap"])
            by_gap_cpu[g].append(float(row["cpu_percent"]))
            by_gap_mem[g].append(float(row["mem_bytes"]) / 1024 / 1024)  # MiB
    return by_gap_cpu, by_gap_mem


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--out", default="attack0.png")
    args = ap.parse_args()

    cpu, mem = load(args.csv)
    gaps = sorted(cpu)
    cpu_mean = [sum(cpu[g]) / len(cpu[g]) for g in gaps]
    cpu_peak = [max(cpu[g]) for g in gaps]
    mem_mean = [sum(mem[g]) / len(mem[g]) for g in gaps]
    mem_peak = [max(mem[g]) for g in gaps]

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; printing table instead\n")
        print(f"{'gap':>6} {'cpu_mean':>9} {'cpu_peak':>9} {'mem_mean':>10} {'mem_peak':>10}")
        for i, g in enumerate(gaps):
            print(f"{g:>6} {cpu_mean[i]:>9.2f} {cpu_peak[i]:>9.2f} "
                  f"{mem_mean[i]:>10.2f} {mem_peak[i]:>10.2f}")
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    ax1.plot(gaps, cpu_mean, "o-", label="mean")
    ax1.plot(gaps, cpu_peak, "s--", label="peak")
    ax1.set_xlabel("forged counter gap (header n ahead of real)")
    ax1.set_ylabel("Bob CPU (%)")
    ax1.set_title("CPU vs counter gap")
    ax1.grid(True, alpha=0.3)
    ax1.legend()

    ax2.plot(gaps, mem_mean, "o-", color="tab:red", label="mean")
    ax2.plot(gaps, mem_peak, "s--", color="tab:orange", label="peak")
    ax2.set_xlabel("forged counter gap (header n ahead of real)")
    ax2.set_ylabel("Bob memory (MiB)")
    ax2.set_title("Memory vs counter gap")
    ax2.grid(True, alpha=0.3)
    ax2.legend()

    fig.tight_layout()
    fig.savefig(args.out, dpi=130)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
