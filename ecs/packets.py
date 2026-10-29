"""Parsers mínimos (stdlib) de Ethernet/IPv4/UDP/TCP/DNS y lectura/escritura pcap."""
import struct
from dataclasses import dataclass, field
from typing import Optional

ETH_P_IP = 0x0800
LINKTYPE_ETHERNET = 1


@dataclass
class Pkt:
    ts: float
    src: str
    dst: str
    ttl: int
    ipid: int
    proto: int
    sport: int = 0
    dport: int = 0
    # TCP
    seq: int = 0
    ack: int = 0
    flags: int = 0
    payload_len: int = 0
    # UDP / DNS
    payload: bytes = b""
    outgoing: Optional[bool] = None  # dirección según AF_PACKET, si se conoce


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def ip4(b: bytes) -> str:
    return "%d.%d.%d.%d" % tuple(b)


def parse_eth(frame: bytes, ts: float, outgoing=None) -> Optional[Pkt]:
    if len(frame) < 14:
        return None
    etype = struct.unpack_from("!H", frame, 12)[0]
    off = 14
    if etype == 0x8100 and len(frame) >= 18:  # VLAN
        etype = struct.unpack_from("!H", frame, 16)[0]
        off = 18
    if etype != ETH_P_IP:
        return None
    return parse_ip(frame[off:], ts, outgoing)


def parse_ip(b: bytes, ts: float, outgoing=None) -> Optional[Pkt]:
    if len(b) < 20 or b[0] >> 4 != 4:
        return None
    ihl = (b[0] & 0x0F) * 4
    total = struct.unpack_from("!H", b, 2)[0]
    ipid = struct.unpack_from("!H", b, 4)[0]
    frag = struct.unpack_from("!H", b, 6)[0]
    if frag & 0x1FFF:  # fragmento no inicial: sin cabecera L4
        return None
    ttl, proto = b[8], b[9]
    p = Pkt(ts, ip4(b[12:16]), ip4(b[16:20]), ttl, ipid, proto, outgoing=outgoing)
    l4 = b[ihl:total] if total >= ihl else b[ihl:]
    if proto == 17 and len(l4) >= 8:
        p.sport, p.dport = struct.unpack_from("!HH", l4, 0)
        p.payload = bytes(l4[8:])
        p.payload_len = len(p.payload)
    elif proto == 6 and len(l4) >= 20:
        p.sport, p.dport, p.seq, p.ack = struct.unpack_from("!HHII", l4, 0)
        doff = (l4[12] >> 4) * 4
        p.flags = l4[13]
        p.payload_len = max(0, len(l4) - doff)
    else:
        return None
    return p


@dataclass
class Dns:
    txid: int
    qr: bool
    rcode: int
    qname: str
    qtype: int
    answers: frozenset = field(default_factory=frozenset)  # (type, rdata bytes)


def _name(b: bytes, off: int, depth=0):
    labels = []
    jumped_end = None
    while True:
        if off >= len(b) or depth > 20:
            raise ValueError("nombre DNS truncado")
        n = b[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack_from("!H", b, off)[0] & 0x3FFF
            if jumped_end is None:
                jumped_end = off + 2
            off = ptr
            depth += 1
            continue
        labels.append(b[off + 1:off + 1 + n].decode("ascii", "replace").lower())
        off += 1 + n
    return ".".join(labels), (jumped_end if jumped_end is not None else off)


def parse_dns(b: bytes) -> Optional[Dns]:
    try:
        if len(b) < 12:
            return None
        txid, fl, qd, an = struct.unpack_from("!HHHH", b, 0)
        off = 12
        if qd != 1:
            return None
        qname, off = _name(b, off)
        qtype = struct.unpack_from("!H", b, off)[0]
        off += 4
        ans = set()
        for _ in range(an):
            _, off = _name(b, off)
            t, _c, _ttl, rdlen = struct.unpack_from("!HHIH", b, off)
            off += 10
            ans.add((t, bytes(b[off:off + rdlen])))
            off += rdlen
        return Dns(txid, bool(fl & 0x8000), fl & 0xF, qname, qtype, frozenset(ans))
    except (ValueError, struct.error):
        return None


def read_pcap(path):
    """Generador de (ts, frame) para pcap clásico Ethernet (µs o ns)."""
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            e = "<"
        else:
            magic = struct.unpack(">I", gh[:4])[0]
            e = ">"
        if magic not in (0xA1B2C3D4, 0xA1B23C4D):
            raise ValueError("no es pcap clásico")
        div = 1e9 if magic == 0xA1B23C4D else 1e6
        link = struct.unpack(e + "I", gh[20:24])[0]
        if link != LINKTYPE_ETHERNET:
            raise ValueError("solo LINKTYPE_ETHERNET")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            s, frac, incl, _orig = struct.unpack(e + "IIII", h)
            yield s + frac / div, f.read(incl)


class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))

    def write(self, ts: float, frame: bytes):
        s = int(ts)
        self.f.write(struct.pack("<IIII", s, int((ts - s) * 1e6), len(frame), len(frame)))
        self.f.write(frame)

    def close(self):
        self.f.close()
