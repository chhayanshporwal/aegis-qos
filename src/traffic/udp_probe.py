#!/usr/bin/env python3
"""
AegisQoS — UDP Probe Client (src/traffic/udp_probe.py)

Interactive UDP probe generator running inside ns_clients.
Sends timestamped packets to a UDP reflector, measures RTT,
RFC 3550 jitter, and packet loss, outputting JSON records.
"""

import sys
import time
import json
import socket
import struct
import argparse
import signal

def run_probe(target_ip: str, port: int, packet_rate_hz: int, packet_size: int, duration: float):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)
    target = (target_ip, port)
    
    interval = 1.0 / max(1, packet_rate_hz)
    payload_len = max(0, packet_size - 16)
    payload = b"A" * payload_len

    seq = 0
    prev_transit = None
    jitter = 0.0
    start_time = time.time()
    
    running = True
    def handle_sig(sig, frame):
        nonlocal running
        running = False
    
    signal.signal(signal.SIGTERM, handle_sig)
    signal.signal(signal.SIGINT, handle_sig)

    while running and (time.time() - start_time < duration):
        seq += 1
        tx_time = time.time()
        packet = struct.pack("!Id", seq, tx_time) + payload
        
        try:
            sock.sendto(packet, target)
            resp, _ = sock.recvfrom(2048)
            rx_time = time.time()
            rtt_ms = (rx_time - tx_time) * 1000.0
            
            # RFC 3550 jitter calculation
            transit = rtt_ms
            if prev_transit is not None:
                jitter += (abs(transit - prev_transit) - jitter) / 16.0
            prev_transit = transit
            
            record = {
                "seq": seq,
                "rtt_ms": round(rtt_ms, 2),
                "jitter_ms": round(jitter, 2),
                "lost": 0,
                "timestamp": round(rx_time, 3),
            }
        except socket.timeout:
            record = {
                "seq": seq,
                "rtt_ms": 0.0,
                "jitter_ms": round(jitter, 2),
                "lost": 1,
                "timestamp": round(time.time(), 3),
            }
        except Exception:
            break
            
        sys.stdout.write(json.dumps(record) + "\n")
        sys.stdout.flush()
        
        # Sleep remainder of interval
        elapsed = time.time() - tx_time
        if elapsed < interval:
            time.sleep(interval - elapsed)

    sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=str, required=True, help="Target server IP")
    parser.add_argument("--port", type=int, required=True, help="Target UDP port")
    parser.add_argument("--rate", type=int, default=50, help="Packet rate in Hz")
    parser.add_argument("--size", type=int, default=160, help="Packet size in bytes")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration in seconds")
    args = parser.parse_args()
    run_probe(args.target, args.port, args.rate, args.size, args.duration)
