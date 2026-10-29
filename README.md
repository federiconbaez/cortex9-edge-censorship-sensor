# cortex9-edge-censorship-sensor

**Sensor pasivo en el borde de la red que detecta DNS spoofing e inyección de TCP RST** en el
tráfico que ya pasa por la red, sin mandar sondas que delaten a quien lo usa. Es un complemento
pasivo de la medición activa al estilo OONI Probe. Es un MVP de un día: el sensor corre en userspace
(Python stdlib, AF_PACKET o pcap) y viene con un laboratorio reproducible en netns con un middlebox
emulado.

## Tesis

Un inyector en el camino tiene que fabricar paquetes que el extremo real nunca mandó. Si no copia con
exactitud el TTL IP, el IPID y el número de secuencia del extremo real, o si el extremo real sigue
hablando después del RST, un observador pasivo con líneas base por resolver y por flujo lo puede ver.

Señales (detalle en [`ecs/detector.py`](ecs/detector.py)):

| señal | qué mira |
|---|---|
| `dns_race` | más respuestas que consultas para la misma transacción (cliente, puerto, resolver, txid, qname) y con respuestas distintas. Un retransmit legítimo trae tantas respuestas como consultas. |
| `dns_ttl` | el TTL IP de la respuesta difiere en ≥ 2 de la moda del resolver (hacen falta ≥ 3 muestras). |
| `rst_ttl` | el TTL IP del RST difiere en ≥ 2 de la moda del flujo. |
| `rst_ipid` | el IPID del RST no cae en (último IPID del remoto, +256]; si el RST llega antes que cualquier IPID no nulo, se juzga contra el siguiente segmento. Los RST con IPID 0 (socket de control de Linux) solo se juzgan por TTL. |
| `rst_then_traffic` | después del RST llega del remoto, con TTL de línea base, un segmento que termina más allá del seq del RST. |

**Privacidad:** las alertas no llevan IPs ni nombres en claro. El qname va como HMAC-SHA256 con una
sal aleatoria por corrida (en el laboratorio la sal es fija para poder puntuar). Se guardan los puertos
y el txid para correlacionar. El sensor no guarda payloads salvo que se pida `--pcap-out`.

## Resultados (GitHub Actions, run [40818857392](https://github.com/federiconbaez/cortex9-edge-censorship-sensor/actions/runs/40818857392))

Hay 6 corridas: semillas 1, 2 y 3, cada una sin netem y con jitter (`netem delay 5ms 3ms` hacia el
cliente, que reordena paquetes). Cada corrida tiene 1000 consultas DNS y 1000 conexiones TCP, una vez
limpias y otra vez con el middlebox, que inyecta en el 40 % de nombres "bloqueados". Las tablas
completas están en [`results/SUMMARY.md`](results/SUMMARY.md) y los datos por corrida en `results/lab-*.json`.

| métrica | medido | criterio |
|---|---|---|
| FPR en tráfico limpio, por corrida (incluye 182–198 RST legítimos por corrida) | **0 / 2000 en las 6 corridas** (0.00 %) | ≤ 0.5 % |
| dns-lowttl (TTL 30–55) | 1228 / 1228 (100 %) | ≥ 95 % |
| dns-copyttl (TTL igual al real, carrera) | 1174 / 1174 (100 %) | ≥ 95 % |
| rst-lowttl | 552 / 552 (100 %) | ≥ 95 % |
| rst-copyttl (TTL copiado, IPID aleatorio) | 551 / 553 (99.6 %) | ≥ 95 % |
| rst-mimic-client (TTL e IPID copiados, RST solo al cliente) | 576 / 576 (100 %) | ≥ 95 % |
| **rst-mimic-both** (TTL e IPID copiados, RST a ambos extremos) | **1 / 613 (0.2 %)** | punto ciego declarado |
| total sin el punto ciego | 4081 / 4083 (≈ 100 %) | |
| total con todas las familias | 4082 / 4696 (86.9 %) | |
| alertas en eventos no inyectados de las corridas con ataque | 1 en total (en jitter-s2) | |
| CPU del sensor en vivo, en runner de CI | 38–89 µs por paquete | no comparable con un router |

**Historia honesta de los números.** El primer CI con jitter dio un **FPR del 5.35–6.15 %** (run
40815857175). Había dos causas: segmentos reordenados que llegaban después de un RST legítimo, y RST
de control con IPID 0. Las dos correcciones se hicieron mirando las capturas de los runs 40815857175 y
40817312145, y el run 40818857392 volvió a correr con **las mismas semillas** de carga. Las IPs,
puertos, ISN, IPID y tiempos fueron nuevos, pero la mezcla de eventos fue la misma. Una semilla nunca
vista sería una prueba más fuerte.

## Cómo reproducir

```bash
python3 -m unittest discover -s tests -t . -v           # 21 tests con paquetes sintéticos
sudo python3 -m pip install --break-system-packages scapy==2.8.0
sudo env PY=python3 DNS_N=1000 TCP_N=1000 SEED=1 ISEED=101 lab/run_lab.sh "$PWD/work"
#   con reordenamiento: agregar NETEM="delay 5ms 3ms" (falla si sch_netem no está)
python3 lab/score.py work mi-corrida results/lab-mi-corrida.json
python3 lab/summarize.py                                  # sale con 1 si no se cumplen los criterios
# sensor real: sudo python3 -m ecs live --iface eth0 --local-net 192.168.1.0/24 --alerts alertas.jsonl
```

El laboratorio usa tres netns con direcciones de documentación (RFC 5737):
cliente `198.51.100.10` ↔ middlebox ↔ resolver `203.0.113.53` y HTTP `203.0.113.80`. El TTL inicial
queda fijo en 64. El inyector ([`lab/injector.py`](lab/injector.py), scapy) aprende el TTL real del
tráfico que reenvía para emular bien la copia de TTL. El sensor corre en vivo en el cliente, se puntúa
la repetición offline de su captura, y el CI exige que las alertas en vivo y offline coincidan.

## Qué NO está probado (fuera de alcance hoy)

- **OpenWrt, QEMU y eBPF/TC**: no hay imagen OpenWrt ni programa eBPF. El sensor es Python en
  userspace, así que no se midió la CPU de un router (el objetivo de < 5 % sigue abierto).
- **Comparación con OONI** (solapamiento ≥ 70 % en sitios bloqueados conocidos): no se hizo.
- **24 h de tráfico limpio real**: el FPR viene de tráfico sintético del laboratorio (DNS con
  retransmits y CDN rotativo, RST legítimos, puertos cerrados y jitter). Con tráfico real pueden
  aparecer fuentes de FP que no medí: cambios de ruta que mueven el TTL, balanceadores con varios
  hosts detrás de una IP (IPID no monotónico) y anycast.
- **Censores reales**: los inyectores son emulados. No probé contra el GFW ni contra middleboxes comerciales.
- **Puntos ciegos conocidos**: un inyector que copia TTL e IPID y resetea a ambos extremos
  (`rst-mimic-both`, 0.2 %); uno que manda RST con IPID 0 y TTL copiado; y DNS spoofing que además
  descarta la respuesta real sin cambiar el TTL.
- Solo IPv4, solo DNS sobre UDP/53 (DoH y DoT no se ven) y solo RST entrantes.

## Fuentes

Las de la idea están registradas en la base del proyecto. No cito números de terceros en este README.

## English summary

Passive edge sensor for DNS spoofing (answer races and TTL anomalies) and injected TCP RSTs (TTL and
IPID mismatch against a per-flow baseline, and traffic after the RST). In a netns lab with a scapy
middlebox (6 CI runs, 2000 clean events each, with and without reordering jitter) it measured 0 false
positives and 100 % detection on 5 injector families. The mimicking injector that resets both ends
is a declared blind spot (0.2 %). OpenWrt/eBPF, router CPU, real 24 h traffic and the OONI comparison
are not done.

Licencia: Apache-2.0.
