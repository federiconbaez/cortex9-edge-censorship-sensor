"""Carga del cliente (misma semilla en corrida limpia y con ataque).
Nombres ficticios bajo .lab.example; 40 % 'bloqueados'. Ruido legítimo:
retransmits DNS (10 %), dominios cdn rotativos, RST legítimos del servidor
(/rst, 15 %) y conexiones rechazadas al puerto 81 (5 %)."""
import argparse
import json
import random
import socket
import time

ap = argparse.ArgumentParser()
ap.add_argument("--seed", type=int, default=1)
ap.add_argument("--dns", type=int, default=300)
ap.add_argument("--tcp", type=int, default=300)
ap.add_argument("--out", required=True)
a = ap.parse_args()
rng = random.Random(a.seed)
RES, SRV = "203.0.113.53", "203.0.113.80"
log = open(a.out, "w")


def qname_bytes(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"


def name(i, blocked):
    if blocked:
        return f"bloqueado{rng.randrange(50)}.lab.example"
    return (f"cdn{rng.randrange(5)}" if rng.random() < 0.2 else f"sitio{rng.randrange(200)}") + ".lab.example"


for i in range(a.dns):
    blocked = rng.random() < 0.4
    n = name(i, blocked)
    txid = rng.randrange(65536)
    retx = rng.random() < 0.10
    q = txid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname_bytes(n) + b"\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    s.settimeout(0.15)
    s.sendto(q, (RES, 53))
    if retx:
        time.sleep(0.03)
        s.sendto(q, (RES, 53))
    got = 0
    t0 = time.time()
    while time.time() - t0 < 0.15:
        try:
            s.recv(2048)
            got += 1
        except socket.timeout:
            break
    log.write(json.dumps({"kind": "dns", "cport": s.getsockname()[1], "txid": txid, "blocked": blocked,
                          "retx": retx, "answers_seen": got}) + "\n")
    s.close()

for i in range(a.tcp):
    blocked = rng.random() < 0.4
    host = name(i, blocked)
    refused = rng.random() < 0.05
    rst_path = rng.random() < 0.15
    s = socket.socket()
    s.settimeout(1.0)
    outcome = "ok"
    try:
        s.connect((SRV, 81 if refused else 80))
        path = "/rst" if rst_path else "/"
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        n = 0
        while True:
            d = s.recv(4096)
            if not d:
                break
            n += len(d)
        outcome = f"bytes={n}"
    except ConnectionResetError:
        outcome = "reset"
    except ConnectionRefusedError:
        outcome = "refused"
    except socket.timeout:
        outcome = "timeout"
    cport = s.getsockname()[1] if s.fileno() != -1 else None
    log.write(json.dumps({"kind": "tcp", "cport": cport, "blocked": blocked, "refused": refused,
                          "rst_path": rst_path, "outcome": outcome}) + "\n")
    s.close()
log.close()
