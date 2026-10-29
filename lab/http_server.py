"""Servidor TCP de laboratorio en :80. Lee la petición, espera DELAY
(latencia de servidor real), responde 2 KiB. Ruta /rst: cierra con
SO_LINGER=0 (RST legítimo del servidor)."""
import socket
import struct
import sys
import threading
import time

addr = sys.argv[1] if len(sys.argv) > 1 else "203.0.113.80"
DELAY = float(sys.argv[2]) if len(sys.argv) > 2 else 0.1


def handle(c):
    try:
        c.settimeout(3)
        req = b""
        while b"\r\n\r\n" not in req:
            d = c.recv(4096)
            if not d:
                return
            req += d
        time.sleep(DELAY)
        body = b"x" * 2048
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        if b" /rst " in req.split(b"\r\n", 1)[0] + b" ":
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        else:
            c.shutdown(socket.SHUT_WR)
            time.sleep(0.05)
    except OSError:
        pass
    finally:
        c.close()


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, 80))
s.listen(128)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
