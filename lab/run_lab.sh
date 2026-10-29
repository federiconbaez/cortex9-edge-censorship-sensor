#!/usr/bin/env bash
# Corre el laboratorio completo: corrida limpia y corrida con middlebox.
# uso: sudo [PY=python3] [DNS_N=300] [TCP_N=300] [SEED=1] [ISEED=7] [NETEM='delay 5ms 3ms'] lab/run_lab.sh WORKDIR
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "FATAL: run_lab.sh requiere root" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")/.." && pwd)
W=${1:?WORKDIR}; PY=${PY:-python3}
DNS_N=${DNS_N:-300}; TCP_N=${TCP_N:-300}; SEED=${SEED:-1}; ISEED=${ISEED:-7}
SALT=${SALT:-00112233445566778899aabbccddeeff}
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"
"$PY" -c "import scapy" || { echo "FATAL: falta scapy para $PY" >&2; exit 1; }
cleanup() { pkill -f "$HERE/lab/(dns_server|http_server|injector).py" 2>/dev/null || true; "$HERE/lab/topo.sh" down; }
trap cleanup EXIT
mkdir -p "$W"
for mode in clean attack; do
  d="$W/$mode"; rm -rf "$d"; mkdir -p "$d"
  "$HERE/lab/topo.sh" up
  if [ -n "${NETEM:-}" ]; then
    # perturbación hacia el cliente (jitter => reordenamiento); falla si no se puede
    # shellcheck disable=SC2086
    ip netns exec ecs-m tc qdisc add dev m0 root netem $NETEM || { echo "FATAL: no se pudo aplicar netem '$NETEM'" >&2; exit 1; }
    ip netns exec ecs-m tc qdisc show dev m0 | grep -q netem || { echo "FATAL: netem no quedó aplicado" >&2; exit 1; }
  fi
  ip netns exec ecs-s "$PY" "$HERE/lab/dns_server.py" & 
  ip netns exec ecs-s "$PY" "$HERE/lab/http_server.py" 203.0.113.80 0.1 &
  ip netns exec ecs-c "$PY" -c "
import socket,time
for _ in range(50):
    try: socket.create_connection(('203.0.113.80',80),timeout=0.5).close(); break
    except OSError: time.sleep(0.1)
else: raise SystemExit('FATAL: sin conectividad c->s:80')"
  ip netns exec ecs-c "$PY" -m ecs live --iface c0 --local-net 198.51.100.0/24 --salt-hex "$SALT" \
      --pcap-out "$d/capture.pcap" --alerts "$d/alerts-live.jsonl" --stats "$d/stats-live.json" &
  SENSOR=$!
  if [ "$mode" = attack ]; then
    ip netns exec ecs-m "$PY" "$HERE/lab/injector.py" --iface m0 --seed "$ISEED" \
        --truth "$d/truth.jsonl" --ready "$d/injector.ready" &
    INJ=$!
    for _ in $(seq 100); do [ -f "$d/injector.ready" ] && break; sleep 0.1; done
    [ -f "$d/injector.ready" ] || { echo "FATAL: el inyector no arrancó" >&2; exit 1; }
  else
    : > "$d/truth.jsonl"
  fi
  sleep 0.5
  ip netns exec ecs-c "$PY" "$HERE/lab/workload.py" --seed "$SEED" --dns "$DNS_N" --tcp "$TCP_N" --out "$d/workload.jsonl"
  sleep 1.5
  kill -TERM "$SENSOR"; wait "$SENSOR"
  if [ "$mode" = attack ]; then
    kill -TERM "$INJ" 2>/dev/null || true; wait "$INJ" || true
    [ -s "$d/truth.jsonl" ] || { echo "FATAL: el inyector no inyectó nada" >&2; exit 1; }
  fi
  pkill -f "$HERE/lab/(dns_server|http_server).py" || true
  sleep 0.2
  "$HERE/lab/topo.sh" down
  # repetición offline sobre la captura (lo que se puntúa)
  "$PY" -m ecs offline --pcap "$d/capture.pcap" --local-net 198.51.100.0/24 --salt-hex "$SALT" \
      --alerts "$d/alerts.jsonl" --stats "$d/stats.json"
done
chmod -R a+rwX "$W"
echo "laboratorio listo en $W"
