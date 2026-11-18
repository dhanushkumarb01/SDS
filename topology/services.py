"""Tiny service simulator run inside Mininet hosts.

Usage (inside a host):  python3 services.py --name web1 tcp/80 tcp/22 udp/53
TCP: accepts connections, answers with a short banner (HTTP-style for port 80/8080
so curl works) and logs who connected. UDP: echoes datagrams back.
Logs go to /tmp/aegis_svc_<name>.log (shared file system in Mininet).
"""
import argparse
import socket
import socketserver
import threading
import time

LOG = None


def log(msg):
    with open(LOG, "a") as f:
        f.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))


def make_tcp_handler(name, port):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            log("TCP %d connect from %s:%d" % (port, *self.client_address))
            self.request.settimeout(2)
            try:
                self.request.recv(1024)
            except OSError:
                pass
            if port in (80, 8080):
                body = ("%s says hello (port %d)\n" % (name, port)).encode()
                self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                                     + str(len(body)).encode() + b"\r\n\r\n" + body)
            else:
                self.request.sendall(("%s service on %d\n" % (name, port)).encode())
    return Handler


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        data, addr = s.recvfrom(2048)
        log("UDP %d from %s:%d" % (port, *addr))
        s.sendto(data, addr)


def main():
    global LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("services", nargs="*", help="e.g. tcp/80 udp/53")
    a = ap.parse_args()
    LOG = "/tmp/aegis_svc_%s.log" % a.name
    for svc in a.services:
        proto, port = svc.split("/")
        port = int(port)
        if proto == "tcp":
            srv = TCPServer(("0.0.0.0", port), make_tcp_handler(a.name, port))
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        elif proto == "udp":
            threading.Thread(target=udp_echo, args=(port,), daemon=True).start()
        log("listening %s" % svc)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
