"""CLI: ecs offline --pcap F | ecs live --iface I [--pcap-out F] [--seconds S]."""
import argparse
import json
import resource
import socket
import sys
import time

from .detector import Detector
from .packets import PcapWriter, parse_eth, read_pcap

ETH_P_ALL = 0x0003


def cpu_s():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ecs")
    ap.add_argument("mode", choices=["offline", "live"])
    ap.add_argument("--pcap")
    ap.add_argument("--iface")
    ap.add_argument("--pcap-out")
    ap.add_argument("--seconds", type=float, default=0, help="live: duración (0 = hasta SIGINT/SIGTERM)")
    ap.add_argument("--local-net", action="append", required=True, help="prefijo(s) del lado local (LAN)")
    ap.add_argument("--ttl-delta", type=int, default=2)
    ap.add_argument("--ipid-min-samples", type=int, default=1)
    ap.add_argument("--salt-hex", help="sal fija (solo para reproducibilidad en el laboratorio)")
    ap.add_argument("--alerts", default="-", help="archivo JSONL de alertas (- = stdout)")
    ap.add_argument("--stats")
    a = ap.parse_args(argv)
    det = Detector(a.local_net, ttl_delta=a.ttl_delta, ipid_min_samples=a.ipid_min_samples,
                   salt=bytes.fromhex(a.salt_hex) if a.salt_hex else None)
    c0, t0 = cpu_s(), time.time()
    if a.mode == "offline":
        if not a.pcap:
            ap.error("offline requiere --pcap")
        for ts, fr in read_pcap(a.pcap):
            p = parse_eth(fr, ts)
            if p:
                det.feed(p)
    else:
        if not a.iface:
            ap.error("live requiere --iface")
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((a.iface, 0))
        s.settimeout(0.2)
        w = PcapWriter(a.pcap_out) if a.pcap_out else None
        import signal
        stop = {"v": False}
        signal.signal(signal.SIGTERM, lambda *_: stop.update(v=True))
        try:
            while not stop["v"] and (a.seconds == 0 or time.time() - t0 < a.seconds):
                try:
                    fr, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                ts = time.time()
                if w:
                    w.write(ts, fr)
                p = parse_eth(fr, ts, outgoing=(addr[2] == socket.PACKET_OUTGOING))
                if p:
                    det.feed(p)
        except KeyboardInterrupt:
            pass
        finally:
            if w:
                w.close()
    stats = dict(det.stats)
    stats["cpu_s"] = round(cpu_s() - c0, 4)
    stats["alerts"] = len(det.alerts)
    out = sys.stdout if a.alerts == "-" else open(a.alerts, "w")
    for al in det.alerts:
        out.write(json.dumps(al, sort_keys=True) + "\n")
    if out is not sys.stdout:
        out.close()
    if a.stats:
        with open(a.stats, "w") as fh:
            json.dump(stats, fh, indent=1, sort_keys=True)
    print(json.dumps(stats, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
