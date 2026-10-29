#!/usr/bin/env bash
# Topología del laboratorio: cliente <-> middlebox <-> servidores, en netns.
# Direcciones de documentación (RFC 5737). Requiere root. Falla en voz alta.
#   ecs-c  c0 198.51.100.10/24  (gw .1)
#   ecs-m  m0 198.51.100.1/24 | m1 203.0.113.1/24   (ip_forward=1)
#   ecs-s  s0 203.0.113.53/24 (DNS) y 203.0.113.80/24 (HTTP)  (gw .1)
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "FATAL: topo.sh requiere root" >&2; exit 1; }
down() { for n in ecs-c ecs-m ecs-s; do ip netns del "$n" 2>/dev/null || true; done; }
case "${1:-}" in
  down) down ;;
  up)
    down
    for n in ecs-c ecs-m ecs-s; do ip netns add "$n"; ip -n "$n" link set lo up; done
    ip link add c0 netns ecs-c type veth peer name m0 netns ecs-m
    ip link add m1 netns ecs-m type veth peer name s0 netns ecs-s
    ip -n ecs-c addr add 198.51.100.10/24 dev c0
    ip -n ecs-m addr add 198.51.100.1/24 dev m0
    ip -n ecs-m addr add 203.0.113.1/24 dev m1
    ip -n ecs-s addr add 203.0.113.53/24 dev s0
    ip -n ecs-s addr add 203.0.113.80/24 dev s0
    for x in "ecs-c c0" "ecs-m m0" "ecs-m m1" "ecs-s s0"; do set -- $x; ip -n "$1" link set "$2" up; done
    # sin offloads: el sensor ve los segmentos tal como van por el cable
    for x in "ecs-c c0" "ecs-m m0" "ecs-m m1" "ecs-s s0"; do set -- $x
      ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true; done
    ip -n ecs-c route add default via 198.51.100.1
    ip -n ecs-s route add default via 203.0.113.1
    ip netns exec ecs-m sysctl -qw net.ipv4.ip_forward=1
    # TTL inicial fijo (el host puede tener otro): el cliente ve 63 del lado remoto
    for n in ecs-c ecs-m ecs-s; do ip netns exec "$n" sysctl -qw net.ipv4.ip_default_ttl=64; done
    ip -n ecs-c route get 203.0.113.80 >/dev/null || { echo "FATAL: sin ruta c->s" >&2; exit 1; }
    echo "topología arriba" ;;
  *) echo "uso: $0 up|down" >&2; exit 1 ;;
esac
