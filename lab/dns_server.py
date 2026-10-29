"""Resolver de laboratorio: responde A para cualquier nombre.
Nombres que empiezan con 'cdn' rotan entre 4 direcciones en cada consulta
(como un CDN real), para ejercitar retransmits legítimos con respuestas distintas."""
import hashlib
import socket
import struct
import sys

sys.path.insert(0, __file__.rsplit("/lab/", 1)[0])
from ecs.packets import parse_dns  # noqa: E402

addr = sys.argv[1] if len(sys.argv) > 1 else "203.0.113.53"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((addr, 53))
rot = {}
while True:
    b, peer = s.recvfrom(2048)
    m = parse_dns(b)
    if m is None or m.qr:
        continue
    h = hashlib.sha256(m.qname.encode()).digest()
    if m.qname.startswith("cdn"):
        i = rot.get(m.qname, 0)
        rot[m.qname] = i + 1
        ip = bytes([192, 0, 2, 100 + i % 4])
    else:
        ip = bytes([192, 0, 2, 1 + h[0] % 90])
    qend = 12 + len(b"".join(bytes([len(x)]) + x.encode() for x in m.qname.split("."))) + 1 + 4
    resp = struct.pack("!HHHHHH", m.txid, 0x8180, 1, 1, 0, 0) + b[12:qend]
    resp += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip
    s.sendto(resp, peer)
