# Attacks — build & run

Lab recap (from the provided `docker-compose.yml`):

```bash
docker compose up as3_server          # terminal 1 — server on :9000
docker compose run --rm bob           # terminal 2 — register + publish bundle FIRST
docker compose run --rm alice         # terminal 3 — sends first
# reset client state between attacks:
docker volume rm as3state             # (or: docker compose down -v)
```

All attacks are plain C++17, no external dependencies.

```bash
g++ -O2 -std=c++17 -o attack0 attack0.cpp -lpthread
g++ -O2 -std=c++17 -o attack1 attack1.cpp -lpthread
g++ -O2 -std=c++17 -o attack2 attack2.cpp -lpthread
```

---

## Attack 0 — skipped-key resource exhaustion (counter manipulation)  [owner: rollno1]

Mallory is a transparent TCP proxy between Bob and the server. She forwards traffic
unchanged except that, in every delivered `Frame`, she rewrites the ratchet header's
message number `n` to be `gap` ahead of its real value (kept ≤ `MAX_SKIP` = 1000 so the
receiver takes the expensive skip path instead of the cheap early `raise`).

Because the receiver derives **and stores** skipped message keys *before* checking the
AEAD tag (`protocol.md` §4.4), each forged frame costs Bob up to ~1000 HMAC
derivations and ~1000 stored keys. The frame itself fails to decrypt (the header is
bound as associated data) but the work is already done, and `st.skipped` grows across
frames → CPU + memory DoS.

```bash
# 1) start Mallory (on the host or Mallory's container), pointing at the real server
./attack0 --listen 0.0.0.0:9100 --server as3_server:9000 --gap 1000

# 2) start Bob pointed at Mallory instead of the server
docker compose run --rm bob /client --server-addr <mallory-ip> --port 9100

# 3) have Alice send messages to Bob as normal; watch Bob's logs show decrypt
#    failures while CPU/mem climb.
```

Measure impact (host side, needs Python 3 + matplotlib for the plot):

```bash
python3 ../scripts/measure.py --container bob --gaps 0,100,250,500,750,1000 \
    --samples 10 --interval 1 --out ../results/attack0.csv
python3 ../scripts/plot.py --csv ../results/attack0.csv --out ../results/attack0.png
```

---

## Attack 1 — one-time prekey exhaustion ("Prekey Pogo")  [owner: rollno2]

> Stub — assigned to teammate. A malicious client repeatedly `fetch_bundle`s Bob to
> drain his OPK inventory, then shows that no new session can be started.

## Attack 2 — malicious-server MITM / key substitution  [owner: rollno2]

> Stub — assigned to teammate. A malicious server component substitutes identity/prekey
> material to run separate sessions with Alice and Bob.

---

## Authorized use

These proof-of-concepts target the provided, self-contained lab (`s4ch1n/as3`) for the
course assignment only.
