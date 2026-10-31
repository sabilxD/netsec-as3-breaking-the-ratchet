# AS3 — Breaking the Ratchet

Coursework for Assignment 3 (Double Ratchet + X3DH lab). Two-person team.

## Layout
```
as3_rollno1_rollno2/
├── state_diagram                 # hand-drawn figure (photo/scan) — TO ADD
├── state_diagram_reference.md    # drawing aid (traced A1→B3 sequence)
├── attacks/
│   ├── README.md                 # build & run instructions
│   ├── attack0.cpp               # [rollno1] counter-manipulation DoS — DONE
│   ├── attack1.cpp               # [rollno2] prekey exhaustion — stub
│   └── attack2.cpp               # [rollno2] malicious-server MITM — stub
├── scripts/
│   ├── measure.py                # docker stats sampler (Attack 0 impact)
│   └── plot.py                   # CPU/mem vs counter-gap plot
├── report/
│   └── 01_intro_and_attack0.md   # [rollno1] report sections
├── results/                      # measurement CSVs + plots (generated)
└── report_rollno1_rollno2.pdf    # final merged report — TO BUILD
```

## Work split
- **rollno1:** lab setup & captures, state diagram, Attack 0 (code + measurement + plots),
  report intro/overview/Attack 0, packaging.
- **rollno2:** Attack 1 (prekey exhaustion), Attack 2 (malicious-server MITM), report
  Attack 1/Attack 2 + conclusion, GenAI appendix.

## Status
- [x] Attack 0 PoC (`attacks/attack0.cpp`, compiles with `g++ -std=c++17`)
- [x] Measurement + plotting scripts
- [x] State-diagram reference (hand drawing still to do)
- [x] Report: intro + Attack 0
- [ ] Attack 1, Attack 2 (rollno2)
- [ ] Run lab, capture real CPU/mem numbers + screenshots
- [ ] Merge report → PDF, final `tar.gz`

## Reminder
Rename `rollno1`/`rollno2` to the real roll numbers (directory, files, report, repo)
before submission. Keep the repo **private** — it holds assignment solutions.
