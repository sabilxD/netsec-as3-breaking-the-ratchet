#!/usr/bin/env python3
"""Attack 0 impact measurement.

Samples Bob's container CPU% and memory via `docker stats` while forged frames with
an increasing counter gap are delivered, and writes a CSV you can plot with plot.py.

Typical use (run on the host while the lab + Mallory + a frame driver are running):

    python3 measure.py --container bob --gaps 0,100,250,500,750,1000 \
        --samples 10 --interval 1 --out ../results/attack0.csv

The script does NOT generate traffic itself; it only samples resource usage. Drive
the forged frames in another terminal (restart Mallory with a new --gap, then send a
message from Alice) between gap steps, or wrap this in your own harness. Each row is
one sample so you can show the mean/peak per gap.
"""
import argparse
import csv
import subprocess
import sys
import time


def sample(container):
    """Return (cpu_percent, mem_bytes, mem_percent) for one docker stats sample."""
    fmt = "{{.CPUPerc}};{{.MemUsage}};{{.MemPerc}}"
    out = subprocess.check_output(
        ["docker", "stats", "--no-stream", "--format", fmt, container],
        text=True,
    ).strip()
    cpu_s, mem_usage, memp_s = out.split(";")
    cpu = float(cpu_s.strip().rstrip("%"))
    memp = float(memp_s.strip().rstrip("%"))
    # mem_usage looks like "12.3MiB / 1.94GiB" -> take the used side.
    used = mem_usage.split("/")[0].strip()
    mem_bytes = parse_size(used)
    return cpu, mem_bytes, memp


def parse_size(s):
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3, "TiB": 1024**4}
    for u, mult in sorted(units.items(), key=lambda kv: -len(kv[0])):
        if s.endswith(u):
            return float(s[: -len(u)].strip()) * mult
    return float(s)  # assume bytes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--container", default="bob")
    ap.add_argument("--gaps", default="0,100,250,500,750,1000",
                    help="comma-separated counter gaps to label each phase")
    ap.add_argument("--samples", type=int, default=10,
                    help="samples per gap phase")
    ap.add_argument("--interval", type=float, default=1.0,
                    help="seconds between samples")
    ap.add_argument("--out", default="attack0.csv")
    args = ap.parse_args()

    gaps = [int(g) for g in args.gaps.split(",") if g.strip()]
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["gap", "sample", "cpu_percent", "mem_bytes", "mem_percent", "ts"])
        for gap in gaps:
            input(f"\n>>> Set Mallory --gap {gap}, trigger a send, then press Enter "
                  f"to sample {args.samples}x...")
            for i in range(args.samples):
                try:
                    cpu, memb, memp = sample(args.container)
                except subprocess.CalledProcessError as e:
                    print(f"docker stats failed: {e}", file=sys.stderr)
                    sys.exit(1)
                w.writerow([gap, i, cpu, memb, memp, time.time()])
                f.flush()
                print(f"gap={gap:5d} sample={i:2d} cpu={cpu:6.2f}% "
                      f"mem={memb/1024/1024:8.2f}MiB ({memp:.2f}%)")
                time.sleep(args.interval)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
