#!/usr/bin/env python3
"""
AegisQoS — Live Zero-DPI Packet Sniffer (src/telemetry/live_sniffer.py)

Captures live network packets using raw socket (socket.AF_PACKET) on Linux.
Strictly adheres to Zero-DPI principle:
  - Reads only the first 54 bytes (Ethernet 14B + IPv4 20B + TCP/UDP 20B).
  - Never touches or inspects Layer 7 application payloads or encrypted content.
  - Extracts L3/L4 statistical metadata: (src_ip, dst_ip, src_port, dst_port, proto, pkt_len, timestamp_ms).
  - Feeds FlowClassifier.record_packet(flow_id, timestamp_ms, pkt_len, proto) in real time.
"""

import os
import sys
import time
import socket
import struct
import threading
from typing import Dict, List, Optional, Tuple, Callable

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.models.flow_classifier import FlowClassifier

# Standard Protocol Numbers
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_IPV6_ICMP = 58

PROTO_NAMES = {
    PROTO_ICMP: "icmp",
    PROTO_TCP: "tcp",
    PROTO_UDP: "udp",
    PROTO_IPV6_ICMP: "ipv6-icmp",
}


def parse_packet_header(raw_bytes: bytes,
                        wire_len: Optional[int] = None) -> Optional[Tuple[str, str, int, int, int, int]]:
    """Parse L2/L3/L4 metadata from raw packet header (Zero-DPI).

    Inspects at most the first 54-64 bytes:
      - Ethernet: 14 bytes (0:14)
      - IPv4: 20 bytes (14:34) -> Proto at 23, Src at 26:30, Dst at 30:34
      - TCP/UDP Ports: 4 bytes (34:38) -> SrcPort at 34:36, DstPort at 36:38
      - IPv6: 40 bytes (14:54) -> NextHeader at 20, Src at 22:38, Dst at 38:54

    Args:
        raw_bytes: Raw captured bytes (minimum 14 bytes).
        wire_len: Actual wire length reported by network interface.

    Returns:
        (src_ip, dst_ip, src_port, dst_port, protocol, packet_length) or None.
    """
    if len(raw_bytes) < 14:
        return None

    eth_type = struct.unpack("!H", raw_bytes[12:14])[0]

    # Handle 802.1Q VLAN tagged frames (EtherType 0x8100)
    offset = 14
    if eth_type == 0x8100:
        if len(raw_bytes) < 18:
            return None
        eth_type = struct.unpack("!H", raw_bytes[16:18])[0]
        offset = 18

    # IPv4 (0x0800)
    if eth_type == 0x0800:
        if len(raw_bytes) < offset + 20:
            return None

        ver_ihl = raw_bytes[offset]
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(raw_bytes) < offset + ihl:
            return None

        total_length = struct.unpack("!H", raw_bytes[offset + 2:offset + 4])[0]
        proto = raw_bytes[offset + 9]
        src_ip = socket.inet_ntoa(raw_bytes[offset + 12:offset + 16])
        dst_ip = socket.inet_ntoa(raw_bytes[offset + 16:offset + 20])

        src_port = 0
        dst_port = 0
        l4_offset = offset + ihl

        if proto in (PROTO_TCP, PROTO_UDP):
            if len(raw_bytes) >= l4_offset + 4:
                src_port, dst_port = struct.unpack("!HH", raw_bytes[l4_offset:l4_offset + 4])

        pkt_len = wire_len if wire_len is not None else (total_length if total_length > 0 else len(raw_bytes))
        return (src_ip, dst_ip, src_port, dst_port, proto, pkt_len)

    # IPv6 (0x86DD)
    elif eth_type == 0x86DD:
        if len(raw_bytes) < offset + 40:
            return None

        payload_len = struct.unpack("!H", raw_bytes[offset + 4:offset + 6])[0]
        next_header = raw_bytes[offset + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, raw_bytes[offset + 8:offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, raw_bytes[offset + 24:offset + 40])

        proto = next_header
        src_port = 0
        dst_port = 0
        l4_offset = offset + 40

        if proto in (PROTO_TCP, PROTO_UDP):
            if len(raw_bytes) >= l4_offset + 4:
                src_port, dst_port = struct.unpack("!HH", raw_bytes[l4_offset:l4_offset + 4])

        pkt_len = wire_len if wire_len is not None else (40 + payload_len)
        return (src_ip, dst_ip, src_port, dst_port, proto, pkt_len)

    return None


class LivePacketSniffer:
    """Zero-DPI Real-Time Raw Packet Sniffer.

    Binds to a physical/virtual network interface using Linux AF_PACKET,
    captures initial 54 bytes of each frame, and feeds flow statistics
    to FlowClassifier in real time.
    """

    def __init__(self,
                 iface: str = "enp0s1",
                 classifier: Optional[FlowClassifier] = None,
                 callback: Optional[Callable] = None,
                 snaplen: int = 54):
        self.iface = iface
        self.classifier = classifier
        self.callback = callback
        self.snaplen = snaplen
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

        # Live counters
        self.packet_count = 0
        self.byte_count = 0
        self.flow_counts: Dict[str, int] = {}
        self.flow_bytes: Dict[str, int] = {}
        self.flow_last_seen: Dict[str, float] = {}
        self._lock = threading.Lock()

    def start(self):
        """Start the live packet sniffer background thread."""
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop packet sniffer and release raw socket."""
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=3.0)

    def _sniff_loop(self):
        """Background loop reading raw frames from network interface."""
        if not hasattr(socket, "AF_PACKET"):
            print(f"[LiveSniffer] Warning: socket.AF_PACKET not available on this OS (Linux required).")
            while self.running:
                time.sleep(0.5)
            return

        try:
            # ETH_P_ALL = 0x0003: capture all ethernet frame types
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            self._sock.bind((self.iface, 0))
            self._sock.settimeout(0.5)
        except PermissionError:
            print(f"[LiveSniffer] Error: Root/sudo privileges required to open raw AF_PACKET socket on {self.iface}.")
            self.running = False
            return
        except Exception as e:
            print(f"[LiveSniffer] Failed to bind to {self.iface}: {e}")
            self.running = False
            return

        print(f"[LiveSniffer] Sniffing Zero-DPI L3/L4 headers on {self.iface} (snaplen={self.snaplen}B)...")

        while self.running:
            try:
                # Strictly read only the first snaplen bytes (Zero-DPI)
                raw_bytes, addr = self._sock.recvfrom(self.snaplen)
            except (socket.timeout, BlockingIOError):
                continue
            except OSError:
                break
            except Exception:
                continue

            now_ms = time.time() * 1000.0

            # Parse L3/L4 metadata
            parsed = parse_packet_header(raw_bytes)
            if not parsed:
                continue

            src_ip, dst_ip, src_port, dst_port, proto, pkt_len = parsed
            proto_name = PROTO_NAMES.get(proto, str(proto))
            flow_id = f"{proto_name}:{src_ip}:{dst_ip}:{src_port}:{dst_port}"

            # Update live metrics
            with self._lock:
                self.packet_count += 1
                self.byte_count += pkt_len
                self.flow_counts[flow_id] = self.flow_counts.get(flow_id, 0) + 1
                self.flow_bytes[flow_id] = self.flow_bytes.get(flow_id, 0) + pkt_len
                self.flow_last_seen[flow_id] = now_ms

            # Feed FlowClassifier in real time
            if self.classifier:
                self.classifier.record_packet(flow_id, now_ms, pkt_len, proto)

            # Optional callback
            if self.callback:
                try:
                    self.callback(flow_id, now_ms, pkt_len, proto, src_ip, dst_ip, src_port, dst_port)
                except Exception:
                    pass

    def get_flow_stats(self, active_within_ms: float = 3000.0) -> List[Dict]:
        """Return list of active flows with current statistics."""
        now_ms = time.time() * 1000.0
        flows = []
        with self._lock:
            for flow_id, last_seen in self.flow_last_seen.items():
                if (now_ms - last_seen) <= active_within_ms:
                    pkts = self.flow_counts.get(flow_id, 0)
                    bytes_val = self.flow_bytes.get(flow_id, 0)
                    parts = flow_id.split(":")
                    proto = parts[0] if len(parts) >= 1 else "unknown"
                    src = f"{parts[1]}:{parts[3]}" if len(parts) >= 5 else ""
                    dst = f"{parts[2]}:{parts[4]}" if len(parts) >= 5 else ""
                    flows.append({
                        "flow_id": flow_id,
                        "proto": proto,
                        "src": src,
                        "dst": dst,
                        "packet_count": pkts,
                        "byte_count": bytes_val,
                        "last_seen_ms_ago": round(now_ms - last_seen, 1),
                    })
        return flows
