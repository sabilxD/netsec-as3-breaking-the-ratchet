#!/usr/bin/env python3
"""Render a DIGITAL GUIDE for the Double Ratchet state diagram (A1..B3).

This is a drawing aid only. The assignment requires a HAND-DRAWN `state_diagram`
brought to the viva — redraw this by hand. Output: results/state_diagram_guide.png

Layout: root-key chain in its own left column; Alice/Bob lanes on the right with one
message arrow per row (red = DH ratchet step, green = symmetric-chain step). Dashed
connectors tie each root-key transition to the message that performs it.
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "results", "state_diagram_guide.png")

fig, ax = plt.subplots(figsize=(14, 9))
ax.set_xlim(0, 14); ax.set_ylim(0, 10.4); ax.axis("off")

RKX = 1.9            # root-key column centre
AL, BO = 6.4, 12.4  # Alice / Bob lane centres

# lanes
ax.text(AL, 9.95, "ALICE", ha="center", fontsize=15, fontweight="bold", color="#0f3460")
ax.text(BO, 9.95, "BOB", ha="center", fontsize=15, fontweight="bold", color="#7a1f1f")
for x in (AL, BO):
    ax.plot([x, x], [0.8, 9.6], color="#cccccc", lw=1, zorder=0)
ax.text(RKX, 9.95, "ROOT KEY", ha="center", fontsize=12, fontweight="bold",
        color="#16213e")

# message rows (top -> bottom)
rows = {"A1": 8.9, "A2": 7.9, "B1": 6.5, "B2": 5.5, "A3": 4.0, "B3": 2.5}

# root-key boxes, each near the row that creates it
rk = [
    (9.5, "RK0 = sk\n(from X3DH)", None),
    (8.9, "RK1\n← DH(DHA0, SPK_B)", "A1"),
    (6.5, "RK2\n← DH(DHB0, DHA0)", "B1"),
    (4.0, "RK3\n← DH(DHA1, DHB0)", "A3"),
    (2.5, "RK4\n← DH(DHB1, DHA1)", "B3"),
]
prev_y = None
for y, label, row in rk:
    ax.add_patch(FancyBboxPatch((RKX - 1.5, y - 0.42), 3.0, 0.84,
                 boxstyle="round,pad=0.04", fc="#eef2fb", ec="#16213e", lw=1.1, zorder=3))
    ax.text(RKX, y, label, ha="center", va="center", fontsize=8, zorder=4)
    if prev_y is not None:
        ax.add_patch(FancyArrowPatch((RKX, prev_y - 0.44), (RKX, y + 0.44),
                     arrowstyle="-|>", mutation_scale=11, color="#16213e", lw=1.1,
                     zorder=2))
    prev_y = y
    if row:  # dashed connector to the message that performs this ratchet
        ax.plot([RKX + 1.5, AL - 1.0], [y, rows[row]], ls=(0, (3, 3)), color="#b03030",
                lw=0.9, zorder=1)


def msg(key, x1, x2, label, sub, dh_ratchet=False):
    y = rows[key]
    col = "#b03030" if dh_ratchet else "#2a6f2a"
    ax.add_patch(FancyArrowPatch((x1, y), (x2, y), arrowstyle="-|>", mutation_scale=16,
                 color=col, lw=2.2, zorder=5))
    midx = (x1 + x2) / 2
    tag = "DH ratchet" if dh_ratchet else "symmetric step"
    ax.text(midx, y + 0.20, label, ha="center", fontsize=9.5, fontweight="bold",
            color=col)
    ax.text(midx, y - 0.28, sub, ha="center", fontsize=7.6, color="#333333")
    ax.text(midx, y - 0.50, f"[{tag}]", ha="center", fontsize=7, style="italic",
            color=col)


msg("A1", AL + 1.0, BO - 1.0, "A1  (dh=DHA0, n=0, pn=0)",
    "Alice: CK_A0→MK_A1  |  Bob: DH-ratchet to RK2, then MK_A1", dh_ratchet=True)
msg("A2", AL + 1.0, BO - 1.0, "A2  (dh=DHA0, n=1, pn=0)",
    "same chain: CK_A0→MK_A2 on both sides")
msg("B1", BO - 1.0, AL + 1.0, "B1  (dh=DHB0, n=0, pn=0)",
    "Bob: CK_B0→MK_B1  |  Alice: DH-ratchet to RK3, then MK_B1", dh_ratchet=True)
msg("B2", BO - 1.0, AL + 1.0, "B2  (dh=DHB0, n=1, pn=0)",
    "same chain: CK_B0→MK_B2 on both sides")
msg("A3", AL + 1.0, BO - 1.0, "A3  (dh=DHA1, n=0, pn=2)",
    "Alice: CK_A1→MK_A3  |  Bob: DH-ratchet to RK4, then MK_A3", dh_ratchet=True)
msg("B3", BO - 1.0, AL + 1.0, "B3  (dh=DHB1, n=0, pn=2)",
    "Bob: CK_B1→MK_B3  |  Alice receives on new chain")

# chain correspondence + legend
ax.text(9.4, 1.25,
        "Chain correspondence:  Alice-send CK_A0 = Bob-recv CK_A0   •   "
        "Bob-send CK_B0 = Alice-recv CK_B0\n"
        "CK_A1 (A3) = Bob-recv CK_A1   •   CK_B1 (B3) = Alice-recv CK_B1",
        ha="center", fontsize=8, color="#444444",
        bbox=dict(boxstyle="round", fc="#f7f7fb", ec="#cccccc"))
ax.add_patch(FancyArrowPatch((0.5, 0.45), (1.5, 0.45), arrowstyle="-|>",
             mutation_scale=13, color="#b03030", lw=2.2))
ax.text(1.65, 0.45, "DH ratchet step", va="center", fontsize=8)
ax.add_patch(FancyArrowPatch((4.3, 0.45), (5.3, 0.45), arrowstyle="-|>",
             mutation_scale=13, color="#2a6f2a", lw=2.2))
ax.text(5.45, 0.45, "symmetric-chain step", va="center", fontsize=8)

ax.text(7, 10.25, "DIGITAL GUIDE — redraw by hand for submission (state_diagram)",
        ha="center", fontsize=9, color="#999999", style="italic")

fig.tight_layout()
fig.savefig(OUT, dpi=140, bbox_inches="tight")
print("wrote", OUT)
