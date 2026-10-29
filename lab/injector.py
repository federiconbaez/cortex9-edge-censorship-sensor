"""Middlebox emulado (corre en ecs-m, mira la interfaz hacia el cliente).

DNS: si la consulta es de un nombre bloqueado, inyecta una respuesta falsa
(192.0.2.66) en carrera con la real (que se reenvía igual). Familias:
  dns-lowttl   TTL IP aleatorio 30..55
  dns-copyttl  TTL IP 63 (igual al de las respuestas reales en el cliente)
TCP: si el segmento cliente->servidor lleva 'Host: bloqueado', inyecta RST.
  rst-lowttl          al cliente y al servidor, TTL 30..55, IPID aleatorio
  rst-copyttl         a ambos, TTL 63, IPID aleatorio
  rst-mimic-both      a ambos, TTL 63, IPID = último IPID del servidor + 1
  rst-mimic-client    solo al cliente, TTL 63, IPID mimetizado (el servidor
                      sigue y su respuesta llega después del RST)
Registra cada inyección (verdad de campo) en JSONL."""
import argparse
import json
import random
import signal
import sys
import threading
import time

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, AsyncSniffer, conf  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--iface", default="m0")
ap.add_argument("--seed", type=int, default=7)
ap.add_argument("--truth", required=True)
ap.add_argument("--ready", required=True)
ap.add_argument("--seconds", type=float, default=600)
a = ap.parse_args()
rng = random.Random(a.seed)
truth = open(a.truth, "w")
L3 = conf.L3socket()
last_ipid = {}
seen_ttl = {}  # (proto) -> TTL con que el cliente ve al remoto real (aprendido del tráfico reenviado)
DNS_FAM = ["dns-lowttl", "dns-copyttl"]
RST_FAM = ["rst-lowttl", "rst-copyttl", "rst-mimic-both", "rst-mimic-client"]
done = set()
fake_ids = set()


LOCK = threading.Lock()


def log(**kw):
    kw["t"] = round(time.time(), 6)
    with LOCK:
        truth.write(json.dumps(kw, sort_keys=True) + "\n")
        truth.flush()


def on(p):
    if IP not in p:
        return
    ip = p[IP]
    if ip.src.startswith("203.0.113.") and ip.dst.startswith("198.51.100."):
        if TCP in p and not (p[TCP].flags & 0x04) and p[TCP].sport == 80:
            last_ipid[(ip.dst, p[TCP].dport)] = ip.id  # tráfico real servidor->cliente
            seen_ttl["tcp"] = ip.ttl
        elif UDP in p and p[UDP].sport == 53 and ip.id not in fake_ids:
            seen_ttl["dns"] = ip.ttl
        return
    if UDP in p and p[UDP].dport == 53 and DNS in p and p[DNS].qr == 0 and p[DNS].qd is not None:
        qn = p[DNSQR].qname.decode(errors="replace").rstrip(".")
        key = ("dns", p[UDP].sport, p[DNS].id)
        if not qn.startswith("bloqueado") or key in done:
            return
        done.add(key)
        fam = rng.choice(DNS_FAM)
        ttl = rng.randrange(30, 56) if fam == "dns-lowttl" else seen_ttl.get("dns", 63)
        fid = rng.randrange(65536)
        fake_ids.add(fid)
        fake = IP(src=ip.dst, dst=ip.src, ttl=ttl, id=fid) / UDP(sport=53, dport=p[UDP].sport) / DNS(
            id=p[DNS].id, qr=1, aa=0, rd=1, ra=1, qd=DNSQR(qname=qn, qtype="A"),
            an=DNSRR(rrname=qn, type="A", ttl=300, rdata="192.0.2.66"))
        L3.send(fake)
        log(kind="dns", family=fam, cport=p[UDP].sport, txid=p[DNS].id, ttl=ttl)
        return
    if TCP in p and p[TCP].dport == 80 and ip.src.startswith("198.51.100."):
        pl = bytes(p[TCP].payload)
        if b"Host: bloqueado" not in pl:
            return
        key = ("rst", p[TCP].sport)
        if key in done:
            return
        done.add(key)
        fam = rng.choice(RST_FAM)
        t = p[TCP]
        rnd_ttl, rnd_id = rng.randrange(30, 56), rng.randrange(65536)

        def fire():
            if fam == "rst-lowttl":
                ttl, ipid = rnd_ttl, rnd_id
            elif fam == "rst-copyttl":
                ttl, ipid = seen_ttl.get("tcp", 63), rnd_id
            else:
                # mimetiza: espera a ver el ACK real del servidor y usa su IPID + 1
                ttl, ipid = seen_ttl.get("tcp", 63), (last_ipid.get((ip.src, t.sport), 0) + 1) % 65536
            L3.send(IP(src=ip.dst, dst=ip.src, ttl=ttl, id=ipid) / TCP(sport=80, dport=t.sport, flags="R", seq=t.ack))
            if fam != "rst-mimic-client":
                L3.send(IP(src=ip.src, dst=ip.dst, ttl=64) / TCP(sport=t.sport, dport=80, flags="R", seq=t.seq + len(pl)))
            log(kind="rst", family=fam, cport=t.sport, sport=80, ttl=ttl, ipid=ipid)

        if fam.startswith("rst-mimic"):
            threading.Timer(0.02, fire).start()  # el servidor real responde 100 ms después
        else:
            fire()


def interesting(p):
    # filtro en Python: sin depender de tcpdump/libpcap para compilar BPF
    return IP in p and ((UDP in p and p[UDP].dport == 53) or (TCP in p and 80 in (p[TCP].sport, p[TCP].dport)))


stop = {"v": False}
signal.signal(signal.SIGTERM, lambda *_: stop.update(v=True))
signal.signal(signal.SIGINT, lambda *_: stop.update(v=True))
sn = AsyncSniffer(iface=a.iface, prn=on, store=False, lfilter=interesting)
sn.start()
time.sleep(1.0)
open(a.ready, "w").write("ok\n")
t0 = time.time()
try:
    while not stop["v"] and time.time() - t0 < a.seconds:
        time.sleep(0.2)
finally:
    sn.stop()
    truth.close()
    print("injector: fin", file=sys.stderr)
