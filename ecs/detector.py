"""Detector pasivo.

Señales (todas pasivas, sobre el tráfico que ya pasa por el borde):

DNS (respuestas UDP/53 entrantes)
  dns_race  más respuestas que consultas para la misma transacción
            (cliente, puerto, resolver, txid, qname) y con conjuntos de
            respuestas distintos. Un retransmit legítimo trae tantas
            respuestas como consultas; un duplicado de red trae la misma.
  dns_ttl   TTL IP de la respuesta lejos (>= ttl_delta) de la moda de las
            últimas respuestas de ese resolver (necesita >= 3 muestras).

TCP RST entrante, línea base por flujo del lado remoto
  rst_ttl    TTL IP del RST lejos (>= ttl_delta) de la moda del flujo.
  rst_ipid   el remoto venía con IPID no nulo (>= ipid_min_samples muestras,
             def. 1; si hay varias, con saltos 1..ipid_window) y el IPID del
             RST no cae en (último, último + ipid_window].
  rst_then_traffic  después del RST llega del remoto, con el TTL de la
             línea base, un segmento que termina más allá del seq del RST
             (datos nuevos: el extremo real no se enteró del RST). Los
             segmentos reordenados que terminan antes no cuentan.
  Solo se juzga el primer RST entrante de cada flujo.

Las alertas no llevan IPs ni nombres en claro: el qname va como HMAC-SHA256
con una sal por corrida; se conservan puertos y txid para correlacionar.
"""
import hashlib
import hmac
import ipaddress
import os
from collections import Counter, deque

from .packets import TCP_FIN, TCP_RST, parse_dns


def mode(xs):
    return Counter(xs).most_common(1)[0][0]


class Detector:
    def __init__(self, local_nets, ttl_delta=2, ipid_window=256, ipid_min_samples=1, salt=None, window_s=5.0):
        self.local = [ipaddress.ip_network(n) for n in local_nets]
        self.ttl_delta = ttl_delta
        self.ipid_window = ipid_window
        self.ipid_min_samples = ipid_min_samples
        self.salt = salt if salt is not None else os.urandom(16)
        self.window_s = window_s
        self.dns = {}          # key -> {"q": n, "resp": [answers...], "alert": dict|None, "t": ts}
        self.resolver_ttl = {}  # server ip -> deque
        self.flows = {}        # key -> estado
        self.alerts = []
        self.stats = Counter()
        self._last_gc = 0.0

    # -- utilidades
    def _is_local(self, ip):
        a = ipaddress.ip_address(ip)
        return any(a in n for n in self.local)

    def qhash(self, qname):
        return hmac.new(self.salt, qname.encode(), hashlib.sha256).hexdigest()[:16]

    def _alert(self, slot, kind, ts, key, reason):
        a = slot.get("alert")
        if a is None:
            a = {"kind": kind, "ts": round(ts, 6), "reasons": [reason], **key}
            slot["alert"] = a
            self.alerts.append(a)
        elif reason not in a["reasons"]:
            a["reasons"].append(reason)
        return a

    # -- entrada
    def feed(self, p):
        self.stats["packets"] += 1
        if p.ts - self._last_gc > 1.0:
            self._gc(p.ts)
        src_local, dst_local = self._is_local(p.src), self._is_local(p.dst)
        if p.proto == 17 and (p.sport == 53 or p.dport == 53):
            self._dns(p, src_local, dst_local)
        elif p.proto == 6:
            self._tcp(p, src_local, dst_local)

    def _gc(self, now):
        self._last_gc = now
        for d in (self.dns, self.flows):
            for k in [k for k, v in d.items() if now - v["t"] > self.window_s]:
                del d[k]

    # -- DNS
    def _dns(self, p, src_local, dst_local):
        m = parse_dns(p.payload)
        if m is None:
            return
        if not m.qr and src_local and p.dport == 53:
            key = (p.src, p.sport, p.dst, m.txid, m.qname)
            s = self.dns.setdefault(key, {"q": 0, "resp": [], "alert": None, "t": p.ts, "counted": False})
            s["q"] += 1
            s["t"] = p.ts
            return
        if not (m.qr and dst_local and not src_local and p.sport == 53):
            return
        key = (p.dst, p.dport, p.src, m.txid, m.qname)
        s = self.dns.setdefault(key, {"q": 0, "resp": [], "alert": None, "t": p.ts, "counted": False})
        if not s["counted"]:
            s["counted"] = True
            self.stats["dns_events"] += 1
        s["t"] = p.ts
        akey = {"cport": p.dport, "txid": m.txid, "qname_h": self.qhash(m.qname)}
        base = self.resolver_ttl.setdefault(p.src, deque(maxlen=32))
        ttl_bad = len(base) >= 3 and abs(p.ttl - mode(base)) >= self.ttl_delta
        if ttl_bad:
            self._alert(s, "dns", p.ts, akey, "dns_ttl")
        else:
            base.append(p.ttl)
        s["resp"].append(m.answers)
        if len(s["resp"]) > max(1, s["q"]) and len(set(s["resp"])) > 1:
            self._alert(s, "dns", p.ts, akey, "dns_race")

    # -- TCP
    def _tcp(self, p, src_local, dst_local):
        if src_local == dst_local:
            return
        inbound = dst_local
        key = (p.dst, p.dport, p.src, p.sport) if inbound else (p.src, p.sport, p.dst, p.dport)
        f = self.flows.get(key)
        if f is None:
            f = {"ttl": deque(maxlen=16), "ipid": deque(maxlen=8), "rst": [], "alert": None,
                 "t": p.ts, "counted": False}
            self.flows[key] = f
        f["t"] = p.ts
        if not inbound:
            return
        if not f["counted"]:
            f["counted"] = True
            self.stats["tcp_flows"] += 1
        akey = {"cport": key[1], "sport": key[3]}
        if p.flags & TCP_RST:
            self.stats["rst_in"] += 1
            f["rst"].append(p.ts)
            if len(f["rst"]) > 1:
                # Solo se juzga el primer RST: los siguientes son consecuencia
                # (p.ej. RST de Linux con IPID 0 desde el socket de control
                # cuando llegan ACKs a una conexión ya cerrada).
                return
            self.stats["rst_flows"] += 1
            f["rst_seq"] = p.seq
            if f["ttl"] and abs(p.ttl - mode(f["ttl"])) >= self.ttl_delta:
                self._alert(f, "rst", p.ts, akey, "rst_ttl")
            ids = [i for i in f["ipid"] if i != 0]
            if len(ids) >= self.ipid_min_samples and f["ipid"] and f["ipid"][-1] != 0:
                deltas = [(b - a) % 65536 for a, b in zip(ids, ids[1:])]
                if all(1 <= d <= self.ipid_window for d in deltas):
                    d = (p.ipid - ids[-1]) % 65536
                    if not (1 <= d <= self.ipid_window):
                        self._alert(f, "rst", p.ts, akey, "rst_ipid")
            return
        # tráfico normal del remoto
        # Tráfico nuevo después del RST: el segmento termina más allá del seq
        # del RST. Un segmento reordenado (enviado antes del RST) termina en o
        # antes de ese seq y no cuenta.
        end = (p.seq + p.payload_len + (1 if p.flags & TCP_FIN else 0)) % 2**32
        new_data = f["rst"] and 0 < (end - f["rst_seq"]) % 2**32 < 2**31
        if new_data and f["ttl"] and abs(p.ttl - mode(f["ttl"])) < self.ttl_delta \
                and p.ts - f["rst"][0] <= self.window_s:
            self._alert(f, "rst", f["rst"][0], akey, "rst_then_traffic")
        f["ttl"].append(p.ttl)
        f["ipid"].append(p.ipid)
