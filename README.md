# AS3 — Breaking the Ratchet

Coursework for Assignment 3 (Double Ratchet + X3DH lab). Two-person team: 23b1075, 23b1057.

## Layout
```
as3_23b1075_23b1057/
├── state_diagram                 # HAND-DRAWN figure (photo/scan) — still TO ADD by hand
├── state_diagram_reference.md    # traced A1→B3 sequence (text)
├── attacks/
│   ├── README.md                 # build & run instructions
│   ├── attack0.cpp               # [23b1075] counter tamper + mailbox flood — DONE
│   ├── attack1.cpp               # [23b1057] prekey exhaustion — stub
│   └── attack2.cpp               # [23b1057] malicious-server MITM — stub
├── scripts/
│   ├── run_attack0_experiments.sh  # reproduces both Attack 0 measurements
│   ├── plot_attack0.py             # renders the two result figures
│   ├── make_state_diagram_guide.py # renders the digital drawing guide
│   ├── build_report.py             # markdown report/ -> PDF (reportlab)
│   ├── measure.py / plot.py        # generic docker-stats sampler/plotter
├── report/                       # markdown sections -> compiled into the PDF
│   ├── 01_intro_and_attack0.md     # [23b1075] DONE (with real measured data)
│   ├── 02_attack1.md               # [23b1057] placeholder
│   ├── 03_attack2.md               # [23b1057] placeholder
│   └── 06_appendix_genai.md        # GenAI appendix placeholder
├── results/                      # REAL measured data + figures (committed)
│   ├── attack0_counter_sweep.csv/.png
│   ├── attack0_mailbox_flood.csv/.png
│   └── state_diagram_guide.png
├── lab/                          # copies of the provided compose + protocol.md
└── report_23b1075_23b1057.pdf    # compiled report (rebuild: python3 scripts/build_report.py)
```

## Work split
- **23b1075:** lab setup & captures, state diagram, Attack 0 (code + measurement + plots),
  report intro/overview/Attack 0, packaging.
- **23b1057:** Attack 1 (prekey exhaustion), Attack 2 (malicious-server MITM), report
  Attack 1/Attack 2 + conclusion, GenAI appendix.

## Status (23b1075's half)
- [x] Attack 0 PoC — both modes compile + run against the real lab
- [x] **Ran the Docker lab and captured real CPU/mem data** (`results/*.csv`, `*.png`)
- [x] Key finding: counter-manipulation DoS is **prevented** (header is authenticated);
      the real availability flaw is an **unbounded, unrated mailbox**
- [x] State-diagram digital guide (`results/state_diagram_guide.png`)
- [x] Report sections (intro + Attack 0) + compiled PDF
- [ ] **Hand-draw** `state_diagram` from the guide and add the photo (viva requires it)
- [ ] Attack 1, Attack 2 (23b1057)
- [ ] Final `tar.gz`

## Reproduce Attack 0
```bash
docker compose -f lab/docker-compose.yml pull
bash scripts/run_attack0_experiments.sh   # writes results/*.csv
python3 scripts/plot_attack0.py           # writes results/*.png
python3 scripts/build_report.py           # rebuilds the PDF
```

## Note
Keep the repo **private** — it holds assignment solutions.
