#!/usr/bin/env python3
"""
AegisQoS — UDP Reflector Server (src/traffic/udp_reflector.py)

Echo server running inside ns_server that reflects UDP probe packets
with high-precision timestamping for latency and jitter measurement.
"""

import sys
import time
import socket
import struct
import argparse
import signal

def run_reflector(port: int, host: str = "0.0.0.0"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(1.0)
    
    running = True
    def handle_sig(sig, frame):
        nonlocal running
        running = False
    
    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    while running:
        try:
            data, addr = sock.recvfrom(2048)
            if not data or data == b"STOP":
                break
            server_rx = time.time()
            resp = data + struct.pack("!d", server_rx)
            sock.sendto(resp, addr)
        except socket.timeout:
            continue
        except Exception:
            break

    sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True, help="UDP port to bind")
    parser.add_argument("--host", type=str, default="0.0.0.0")
    args = parser.parse_args()
    run_reflector(args.port, args.host)
