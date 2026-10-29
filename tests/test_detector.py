import os
import struct
import tempfile
import unittest

from ecs.detector import Detector
from ecs.packets import TCP_ACK, TCP_PSH, TCP_RST, TCP_SYN, PcapWriter, Pkt, parse_dns, parse_eth, read_pcap

C, R, S = "198.51.100.10", "203.0.113.53", "203.0.113.80"  # RFC 5737
LOCAL = ["198.51.100.0/24"]


def qname_bytes(name):
    return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"


def dns_bytes(txid, name, qr=False, ips=()):
    fl = 0x8180 if qr else 0x0100
    b = struct.pack("!HHHHHH", txid, fl, 1, len(ips), 0, 0) + qname_bytes(name) + struct.pack("!HH", 1, 1)
    for ip in ips:
        b += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(int(x) for x in ip.split("."))
    return b


def q(ts, txid, name, sport=40000):
    return Pkt(ts, C, R, 64, 1, 17, sport, 53, payload=dns_bytes(txid, name))


def r(ts, txid, name, ips, ttl=63, sport=40000):
    return Pkt(ts, R, C, ttl, 2, 17, 53, sport, payload=dns_bytes(txid, name, True, ips))


def tcp(ts, frm_server, flags, ttl=63, ipid=0, cport=50000, plen=0, seq=0):
    if frm_server:
        return Pkt(ts, S, C, ttl, ipid, 6, 80, cport, seq=seq, flags=flags, payload_len=plen)
    return Pkt(ts, C, S, 64, ipid, 6, cport, 80, seq=seq, flags=flags, payload_len=plen)


def det():
    return Detector(LOCAL, salt=b"k" * 16)


def warm_resolver(d, n=4):
    for i in range(n):
        d.feed(q(0.01 * i, 1000 + i, "warm.example", 41000 + i))
        d.feed(r(0.01 * i + 0.001, 1000 + i, "warm.example", ["192.0.2.1"], sport=41000 + i))


class DnsTests(unittest.TestCase):
    def test_parse_dns_con_compresion(self):
        m = parse_dns(dns_bytes(7, "a.b.example", True, ["192.0.2.1", "192.0.2.2"]))
        self.assertEqual((m.txid, m.qr, m.qname, len(m.answers)), (7, True, "a.b.example", 2))

    def test_respuesta_unica_limpia_no_alerta(self):
        d = det()
        warm_resolver(d)
        d.feed(q(1, 5, "ok.example"))
        d.feed(r(1.01, 5, "ok.example", ["192.0.2.7"]))
        self.assertEqual(d.alerts, [])

    def test_carrera_con_respuestas_distintas_alerta(self):
        d = det()
        warm_resolver(d)
        d.feed(q(1, 5, "blocked.example"))
        d.feed(r(1.001, 5, "blocked.example", ["192.0.2.66"]))  # inyectada, TTL copiado
        d.feed(r(1.02, 5, "blocked.example", ["192.0.2.7"]))
        self.assertEqual(len(d.alerts), 1)
        self.assertEqual(d.alerts[0]["reasons"], ["dns_race"])

    def test_retransmit_con_rotacion_no_alerta(self):
        d = det()
        warm_resolver(d)
        d.feed(q(1, 5, "cdn.example"))
        d.feed(q(1.2, 5, "cdn.example"))
        d.feed(r(1.21, 5, "cdn.example", ["192.0.2.7"]))
        d.feed(r(1.22, 5, "cdn.example", ["192.0.2.8"]))
        self.assertEqual(d.alerts, [])

    def test_duplicado_identico_no_alerta(self):
        d = det()
        warm_resolver(d)
        d.feed(q(1, 5, "dup.example"))
        d.feed(r(1.01, 5, "dup.example", ["192.0.2.7"]))
        d.feed(r(1.01, 5, "dup.example", ["192.0.2.7"]))
        self.assertEqual(d.alerts, [])

    def test_ttl_anomalo_alerta_y_no_contamina_linea_base(self):
        d = det()
        warm_resolver(d)
        d.feed(q(1, 5, "x.example"))
        d.feed(r(1.01, 5, "x.example", ["192.0.2.66"], ttl=41))
        self.assertEqual(d.alerts[0]["reasons"], ["dns_ttl"])
        self.assertNotIn(41, d.resolver_ttl[R])

    def test_sin_linea_base_no_juzga_ttl(self):
        d = det()
        d.feed(q(1, 5, "x.example"))
        d.feed(r(1.01, 5, "x.example", ["192.0.2.66"], ttl=41))
        self.assertEqual(d.alerts, [])

    def test_alerta_sin_ip_ni_qname_en_claro(self):
        d = det()
        warm_resolver(d)
        d.feed(q(1, 5, "secreto.example"))
        d.feed(r(1.01, 5, "secreto.example", ["192.0.2.66"], ttl=30))
        blob = repr(d.alerts)
        for s in (C, R, "secreto", "192.0.2.66"):
            self.assertNotIn(s, blob)


def handshake(d, ipid0=100):
    # servidor: ISN 1000; tras el SYN-ACK su seq es 1001; manda 100 bytes -> 1101
    d.feed(tcp(0.0, False, TCP_SYN))
    d.feed(tcp(0.001, True, TCP_SYN | TCP_ACK, ipid=0, seq=1000))
    d.feed(tcp(0.002, False, TCP_ACK))
    d.feed(tcp(0.003, False, TCP_ACK | TCP_PSH, plen=80))
    d.feed(tcp(0.004, True, TCP_ACK, ipid=ipid0, seq=1001))
    d.feed(tcp(0.005, True, TCP_ACK | TCP_PSH, ipid=ipid0 + 1, plen=100, seq=1001))


class TcpTests(unittest.TestCase):
    def test_rst_legitimo_no_alerta(self):
        d = det()
        handshake(d)
        d.feed(tcp(0.01, True, TCP_RST | TCP_ACK, ipid=102))
        self.assertEqual(d.alerts, [])
        self.assertEqual(d.stats["rst_flows"], 1)

    def test_rst_ttl_bajo_alerta(self):
        d = det()
        handshake(d)
        d.feed(tcp(0.01, True, TCP_RST, ttl=47, ipid=102))
        self.assertEqual(d.alerts[0]["reasons"], ["rst_ttl"])
        self.assertEqual((d.alerts[0]["cport"], d.alerts[0]["sport"]), (50000, 80))

    def test_rst_ipid_fuera_de_ventana_alerta(self):
        d = det()
        handshake(d)
        d.feed(tcp(0.01, True, TCP_RST, ipid=40000))
        self.assertEqual(d.alerts[0]["reasons"], ["rst_ipid"])

    def test_rst_ipid_con_una_sola_muestra(self):
        d = det()
        d.feed(tcp(0.0, False, TCP_SYN))
        d.feed(tcp(0.001, True, TCP_SYN | TCP_ACK, ipid=0))
        d.feed(tcp(0.004, True, TCP_ACK, ipid=27655))
        d.feed(tcp(0.005, True, TCP_RST, ipid=57753))
        self.assertEqual(d.alerts[0]["reasons"], ["rst_ipid"])
        d2 = Detector(LOCAL, salt=b"k" * 16, ipid_min_samples=2)
        for p in (tcp(0.0, False, TCP_SYN), tcp(0.001, True, TCP_SYN | TCP_ACK, ipid=0),
                  tcp(0.004, True, TCP_ACK, ipid=27655), tcp(0.005, True, TCP_RST, ipid=57753)):
            d2.feed(p)
        self.assertEqual(d2.alerts, [])

    def test_rst_ipid_cero_tras_ipid_cero_no_alerta(self):
        d = det()
        d.feed(tcp(0.0, False, TCP_SYN))
        d.feed(tcp(0.001, True, TCP_SYN | TCP_ACK, ipid=0))
        d.feed(tcp(0.005, True, TCP_RST, ipid=0))
        self.assertEqual(d.alerts, [])

    def test_rst_ctl_ipid_cero_antes_del_rst_real_no_alerta(self):
        # jitter: llega primero el RST del socket de control (IPID 0, seq atrasado)
        d = det()
        handshake(d)
        d.feed(tcp(0.01, True, TCP_RST, ipid=0, seq=1101))
        d.feed(tcp(0.011, True, TCP_ACK | TCP_PSH, ipid=102, plen=200, seq=1101))
        d.feed(tcp(0.012, True, TCP_RST | TCP_ACK, ipid=103, seq=1301))
        self.assertEqual(d.alerts, [])

    def test_ipid_diferido_cuando_el_rst_llega_primero(self):
        def flujo(rst_ipid):
            d = det()
            d.feed(tcp(0.0, False, TCP_SYN))
            d.feed(tcp(0.001, True, TCP_SYN | TCP_ACK, ipid=0, seq=1000))
            d.feed(tcp(0.002, True, TCP_RST, ipid=rst_ipid, seq=1001))
            d.feed(tcp(0.003, True, TCP_ACK, ipid=5000, seq=1001))  # reordenado
            return d.alerts
        self.assertEqual(flujo(40000)[0]["reasons"], ["rst_ipid"])
        self.assertEqual(flujo(5001), [])

    def test_rst_seguido_de_trafico_real_alerta(self):
        d = det()
        handshake(d)
        d.feed(tcp(0.01, True, TCP_RST, ipid=102, seq=1101))
        self.assertEqual(d.alerts, [])
        d.feed(tcp(0.1, True, TCP_ACK | TCP_PSH, ipid=103, plen=50, seq=1101))
        self.assertEqual(d.alerts[0]["reasons"], ["rst_then_traffic"])

    def test_segmento_reordenado_tras_rst_legitimo_no_alerta(self):
        d = det()
        handshake(d)
        # el servidor mandó 200 bytes más (1101..1301) y luego RST seq=1301;
        # con jitter el RST llega antes que el segmento de datos
        d.feed(tcp(0.01, True, TCP_RST | TCP_ACK, ipid=104, seq=1301))
        d.feed(tcp(0.011, True, TCP_ACK | TCP_PSH, ipid=103, plen=200, seq=1101))
        self.assertEqual(d.alerts, [])

    def test_rst_posterior_con_ipid_cero_no_se_juzga(self):
        d = det()
        handshake(d)
        d.feed(tcp(0.01, True, TCP_RST | TCP_ACK, ipid=102, seq=1101))
        d.feed(tcp(0.02, True, TCP_RST, ipid=0, seq=1101))  # RST del socket de control
        self.assertEqual(d.alerts, [])
        self.assertEqual((d.stats["rst_in"], d.stats["rst_flows"]), (2, 1))

    def test_rst_a_syn_sin_linea_base_no_alerta(self):
        d = det()
        d.feed(tcp(0.0, False, TCP_SYN))
        d.feed(tcp(0.001, True, TCP_RST | TCP_ACK, ttl=63))
        self.assertEqual(d.alerts, [])

    def test_rst_saliente_se_ignora(self):
        d = det()
        handshake(d)
        d.feed(tcp(0.01, False, TCP_RST, ipid=9))
        self.assertEqual(d.alerts, [])
        self.assertEqual(d.stats["rst_in"], 0)


class PcapTests(unittest.TestCase):
    def test_ida_y_vuelta_pcap(self):
        ip = bytearray(20)
        ip[0], ip[8], ip[9] = 0x45, 63, 17
        body = struct.pack("!HHHH", 53, 40000, 8 + 12, 0) + dns_bytes(1, "a.example", True)[:12]
        struct.pack_into("!H", ip, 2, 20 + len(body))
        ip[12:16], ip[16:20] = bytes([203, 0, 113, 53]), bytes([198, 51, 100, 10])
        frame = b"\x00" * 12 + b"\x08\x00" + bytes(ip) + body
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "x.pcap")
            w = PcapWriter(path)
            w.write(1.5, frame)
            w.close()
            got = list(read_pcap(path))
        self.assertEqual(len(got), 1)
        p = parse_eth(got[0][1], got[0][0])
        self.assertEqual((p.src, p.ttl, p.sport), (R, 63, 53))


if __name__ == "__main__":
    unittest.main()
