#!/usr/bin/env python3
"""Render Attack 0 figures from the measured CSVs in results/.

  python3 plot_attack0.py   # reads ../results/*.csv, writes ../results/*.png

Two figures:
  1) attack0_counter_sweep.png  — Bob CPU/mem vs forged counter gap (shows the
     counter-manipulation attack is PREVENTED: forged frames stay at/below baseline).
  2) attack0_mailbox_flood.png  — server memory vs injected frames (the real
     availability flaw: unbounded mailbox growth, no quota/rate limit).
"""
import csv
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
RES = os.path.join(HERE, "..", "results")


def read(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def counter_sweep():
    rows = read(os.path.join(RES, "attack0_counter_sweep.csv"))
    gap = [int(r["gap"]) for r in rows]
    cpu = [float(r["bob_peak_cpu_pct"]) for r in rows]
    mem = [float(r["bob_peak_mem_mib"]) for r in rows]
    base_cpu = cpu[gap.index(0)] if 0 in gap else None

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2))
    ax1.plot(gap, cpu, "o-", color="tab:blue")
    if base_cpu is not None:
        ax1.axhline(base_cpu, ls="--", color="gray", alpha=0.7,
                    label=f"gap=0 baseline ({base_cpu:.1f}%)")
        ax1.legend()
    ax1.set_xlabel("forged counter gap (header n pushed ahead)")
    ax1.set_ylabel("Bob peak CPU (%)")
    ax1.set_title("Counter attack: Bob CPU vs gap\n(forged frames fail auth cheaply)")
    ax1.grid(True, alpha=0.3)

    ax2.plot(gap, mem, "s-", color="tab:green")
    ax2.set_xlabel("forged counter gap (header n pushed ahead)")
    ax2.set_ylabel("Bob peak memory (MiB)")
    ax2.set_title("Counter attack: Bob memory vs gap\n(flat — no skipped-key growth)")
    ax2.grid(True, alpha=0.3)

    fig.tight_layout()
    out = os.path.join(RES, "attack0_counter_sweep.png")
    fig.savefig(out, dpi=130)
    print("wrote", out)


def mailbox_flood():
    rows = read(os.path.join(RES, "attack0_mailbox_flood.csv"))
    n = [int(r["injected_frames"]) for r in rows]
    mem = [float(r["server_mem_mib"]) for r in rows]

    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    ax.plot(n, mem, "o-", color="tab:red")
    ax.set_xlabel("junk frames injected into Bob's mailbox")
    ax.set_ylabel("server memory (MiB)")
    ax.set_title("Mailbox flood: unbounded server memory growth\n"
                 "(unauthenticated-quota mailbox, no rate limit)")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    out = os.path.join(RES, "attack0_mailbox_flood.png")
    fig.savefig(out, dpi=130)
    print("wrote", out)


if __name__ == "__main__":
    counter_sweep()
    mailbox_flood()
