#!/usr/bin/env bash
# Reproduce the Attack 0 measurements end-to-end on the provided lab.
# Produces:
#   results/attack0_counter_sweep.csv   (counter attack -> prevented; CPU/mem vs gap)
#   results/attack0_mailbox_flood.csv   (mailbox flood -> the real DoS; server mem vs N)
# then plot with:  python3 scripts/plot_attack0.py
#
# Run from the submission root:  bash scripts/run_attack0_experiments.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="$ROOT/lab"
BUILD="$ROOT/attacks/build"
RES="$ROOT/results"
mkdir -p "$BUILD" "$RES"
IMG="s4ch1n/as3:latest"
N=300   # frames per gap in the counter sweep

echo "[*] building Mallory (linux static)"
docker run --rm -v "$ROOT/attacks:/src" gcc:13 \
  bash -c "g++ -O2 -std=c++17 -static -o /src/build/mallory /src/attack0.cpp -lpthread" 2>/dev/null

echo "[*] ensuring server is up"
docker compose -f "$LAB/docker-compose.yml" up -d as3_server >/dev/null 2>&1

# ---- Experiment 1: counter-manipulation sweep -------------------------------
echo "gap,bob_peak_cpu_pct,bob_peak_mem_mib,frames_failed,frames_ok" > "$RES/attack0_counter_sweep.csv"
for GAP in 0 100 500 1000 2000 5000; do
  docker rm -f bob alice mallory >/dev/null 2>&1
  docker compose -f "$LAB/docker-compose.yml" restart as3_server >/dev/null 2>&1; sleep 2
  docker run -d --name mallory --network as3net -v "$BUILD:/b" debian:stable-slim \
    /b/mallory --listen 0.0.0.0:9100 --server as3_server:9000 --gap "$GAP" >/dev/null 2>&1
  sleep 1
  docker run -d -i --name bob --network as3net -e USER_NAME=bob -e STATE_DIR=/state \
    --entrypoint /client "$IMG" --server-addr mallory --port 9100 >/dev/null
  sleep 2
  S="$(mktemp)"
  ( for i in $(seq 1 30); do docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' bob 2>/dev/null >> "$S"; done ) &
  SP=$!
  { printf '1\nbob\n'; for i in $(seq 1 "$N"); do printf 'm%d\n' "$i"; done; } \
    | docker run --rm -i --name alice --network as3net -e USER_NAME=alice -e STATE_DIR=/state \
      --entrypoint "$IMG" --server-addr as3_server --port 9000 >/dev/null 2>&1 || true
  sleep 5
  kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null
  PCPU=$(awk '{c=$1; gsub(/%/,"",c); if(c+0>m)m=c+0} END{printf "%.2f", m}' "$S")
  PMEM=$(awk '{if(index($2,"MiB")){n=$2; sub(/MiB/,"",n); if(n+0>m)m=n+0}} END{printf "%.2f", m}' "$S")
  FAIL=$(docker logs bob 2>&1 | grep -c 'DECRYPT FAIL')
  OK=$(docker logs bob 2>&1 | grep -c 'recv <-')
  echo "${GAP},${PCPU},${PMEM},${FAIL},${OK}" | tee -a "$RES/attack0_counter_sweep.csv"
  rm -f "$S"
done

# ---- Experiment 2: mailbox flood -------------------------------------------
echo "[*] mailbox flood"
docker rm -f bob alice mallory >/dev/null 2>&1
docker compose -f "$LAB/docker-compose.yml" restart as3_server >/dev/null 2>&1; sleep 2
echo "injected_frames,server_mem_mib" > "$RES/attack0_mailbox_flood.csv"
mem() { docker stats --no-stream --format '{{.MemUsage}}' as3_server | awk '{n=$1; if(index($1,"GiB")){sub(/GiB/,"",n); print n*1024} else {sub(/MiB/,"",n); print n}}'; }
echo "0,$(mem)" | tee -a "$RES/attack0_mailbox_flood.csv"
TOTAL=0
for STEP in 20000 30000 50000 100000 200000; do
  docker run --rm --network as3net -v "$BUILD:/b" debian:stable-slim \
    /b/mallory --flood-mailbox --server as3_server:9000 --as evil --target bob --count "$STEP" >/dev/null 2>&1
  TOTAL=$((TOTAL+STEP)); sleep 1
  echo "${TOTAL},$(mem)" | tee -a "$RES/attack0_mailbox_flood.csv"
done

docker rm -f bob alice mallory >/dev/null 2>&1
echo "[*] done. plot with: python3 scripts/plot_attack0.py"
