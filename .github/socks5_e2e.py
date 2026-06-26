#!/usr/bin/env python3
"""Self-contained black-box check for the socks5-rs server.

Starts local TCP and UDP echo services, then exercises CONNECT and
UDP ASSOCIATE through the proxy listening on 127.0.0.1:8080. Uses only the
Python standard library (no pysocks, no external downloads).

Exits 0 on success, non-zero on the first failed check.
"""

import socket
import struct
import sys
import threading
import time

PROXY = ("127.0.0.1", 8080)


def start_tcp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def handle(conn):
        with conn:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)

    def loop():
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()


def start_udp_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))

    def loop():
        while True:
            data, src = srv.recvfrom(65535)
            srv.sendto(data, src)

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()


def wait_for_proxy(timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(PROXY, timeout=1).close()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"proxy {PROXY} did not come up within {timeout}s")


def greet(sock):
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    assert resp == b"\x05\x00", f"greeting failed: {resp!r}"


def check_connect(target):
    s = socket.create_connection(PROXY, timeout=5)
    greet(s)
    req = b"\x05\x01\x00\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1])
    s.sendall(req)
    reply = s.recv(10)
    assert reply[1] == 0x00, f"CONNECT failed: REP={reply[1]:#x}"
    s.sendall(b"hello-connect")
    got = s.recv(64)
    assert got == b"hello-connect", f"CONNECT echo mismatch: {got!r}"
    s.close()
    print("CONNECT OK")


def check_udp(target):
    ctrl = socket.create_connection(PROXY, timeout=5)
    greet(ctrl)
    # UDP ASSOCIATE with DST 0.0.0.0:0
    ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply = ctrl.recv(10)
    assert reply[1] == 0x00, f"UDP ASSOCIATE failed: REP={reply[1]:#x}"
    bnd_ip = socket.inet_ntoa(reply[4:8])
    bnd_port = struct.unpack("!H", reply[8:10])[0]
    relay = ("127.0.0.1" if bnd_ip == "0.0.0.0" else bnd_ip, bnd_port)

    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(5)
    header = b"\x00\x00\x00\x01" + socket.inet_aton(target[0]) + struct.pack("!H", target[1])
    u.sendto(header + b"hello-udp", relay)
    resp, _ = u.recvfrom(65535)
    assert resp[:3] == b"\x00\x00\x00", f"bad RSV/FRAG in reply: {resp[:3]!r}"
    assert resp[3] == 0x01, "expected IPv4 ATYP in reply"
    assert resp[10:] == b"hello-udp", f"UDP echo mismatch: {resp[10:]!r}"
    ctrl.close()
    print("UDP ASSOCIATE OK")


def main():
    tcp_target = start_tcp_echo()
    udp_target = start_udp_echo()
    try:
        wait_for_proxy()
        check_connect(tcp_target)
        check_udp(udp_target)
    except Exception as e:  # noqa: BLE001 - report any failure and fail the job
        print(f"E2E FAILED: {e}", file=sys.stderr)
        sys.exit(1)
    print("all e2e checks passed")


if __name__ == "__main__":
    main()
