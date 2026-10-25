#!/usr/bin/env python3
"""
Tests for AegisQoS Live Real-Wi-Fi Mode, Zero-DPI Sniffer, and Scenario 4.
"""

import os
import sys
import socket
import struct
import time
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.enforcement.tc_enforcer import TcEnforcer
from src.telemetry.live_sniffer import parse_packet_header, LivePacketSniffer
from src.models.flow_classifier import FlowClassifier
from src.traffic.scenario_generator import SwarmTransferWorker, ScenarioGenerator, RegimeController


class TestControlPlaneAndAckFastPath:
    """Test control-plane DNS and TCP ACK fast-path iptables rules."""

    def test_dns_rules_marked_0x10(self):
        """DNS queries and responses must be marked 0x10 (Class 0: Realtime)."""
        enforcer = TcEnforcer()
        rules = enforcer.generate_iptables_rules(flow_marks=None, include_icmp=True)

        # Check IPv4 and IPv6 DNS rules with mark 0x10
        has_udp_dport_53 = any("-p udp --dport 53 -j MARK --set-mark 0x10" in r for r in rules)
        has_udp_sport_53 = any("-p udp --sport 53 -j MARK --set-mark 0x10" in r for r in rules)
        has_tcp_dport_53 = any("-p tcp --dport 53 -j MARK --set-mark 0x10" in r for r in rules)
        has_ip6_dns = any("ip6tables" in r and "53" in r and "0x10" in r for r in rules)

        assert has_udp_dport_53, "Missing DNS UDP dport 53 rule with mark 0x10"
        assert has_udp_sport_53, "Missing DNS UDP sport 53 rule with mark 0x10"
        assert has_tcp_dport_53, "Missing DNS TCP dport 53 rule with mark 0x10"
        assert has_ip6_dns, "Missing IPv6 DNS rule with mark 0x10"

        # Verify DNS is not marked as 0x30
        assert not any("53 -j MARK --set-mark 0x30" in r for r in rules), "DNS should not be marked 0x30"

    def test_tcp_syn_and_small_ack_marked_0x10(self):
        """TCP SYN and small ACK packets (0:128) must be marked 0x10 for fast-path."""
        enforcer = TcEnforcer()
        rules = enforcer.generate_iptables_rules(flow_marks=None, include_icmp=True)

        has_small_ack = any(
            "-p tcp -m tcp --tcp-flags SYN,RST,ACK ACK -m length --length 0:128 -j MARK --set-mark 0x10" in r
            for r in rules
        )
        has_syn = any(
            "-p tcp -m tcp --tcp-flags SYN,RST SYN -j MARK --set-mark 0x10" in r
            for r in rules
        )
        has_ip6_small_ack = any(
            "ip6tables" in r and "0:128" in r and "0x10" in r
            for r in rules
        )

        assert has_small_ack, "Missing TCP small ACK fast-path rule"
        assert has_syn, "Missing TCP SYN fast-path rule"
        assert has_ip6_small_ack, "Missing IPv6 TCP small ACK fast-path rule"

    def test_host_namespace_prefix(self):
        """When namespace=None (live host mode), rules must not prefix with ip netns exec."""
        enforcer = TcEnforcer(namespace=None)
        rules = enforcer.generate_iptables_rules(flow_marks=None, include_icmp=True)
        assert enforcer.ns_prefix == ""
        assert not any("ip netns exec" in r for r in rules)
        assert any(r.startswith("iptables") for r in rules)


class TestLivePacketSniffer:
    """Test Zero-DPI packet header parsing across protocols."""

    def test_parse_ipv4_udp_packet(self):
        """Parse raw Ethernet + IPv4 + UDP packet header."""
        # 14 bytes Ethernet
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        # 20 bytes IPv4 (UDP proto=17, src=192.168.1.50, dst=1.1.1.1, total_len=100)
        src_ip = socket.inet_aton("192.168.1.50")
        dst_ip = socket.inet_aton("1.1.1.1")
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
                             0x45, 0x00, 100, 0x1234, 0x0000, 64, 17, 0x0000, src_ip, dst_ip)
        # 4 bytes L4 ports (src=55005, dst=53)
        udp_hdr = struct.pack("!HH", 55005, 53)

        raw = eth + ip_hdr + udp_hdr
        assert len(raw) == 14 + 20 + 4  # 38 bytes <= 54 bytes (Zero-DPI)

        res = parse_packet_header(raw)
        assert res is not None
        s_ip, d_ip, s_port, d_port, proto, pkt_len = res
        assert s_ip == "192.168.1.50"
        assert d_ip == "1.1.1.1"
        assert s_port == 55005
        assert d_port == 53
        assert proto == 17
        assert pkt_len == 100

    def test_parse_ipv4_tcp_packet(self):
        """Parse raw Ethernet + IPv4 + TCP packet header."""
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        src_ip = socket.inet_aton("10.0.1.2")
        dst_ip = socket.inet_aton("10.0.3.2")
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
                             0x45, 0x00, 1500, 0x4321, 0x0000, 64, 6, 0x0000, src_ip, dst_ip)
        tcp_hdr = struct.pack("!HH", 5201, 45678)

        raw = eth + ip_hdr + tcp_hdr
        res = parse_packet_header(raw)
        assert res is not None
        s_ip, d_ip, s_port, d_port, proto, pkt_len = res
        assert s_ip == "10.0.1.2"
        assert d_ip == "10.0.3.2"
        assert s_port == 5201
        assert d_port == 45678
        assert proto == 6
        assert pkt_len == 1500

    def test_parse_ipv6_udp_packet(self):
        """Parse raw Ethernet + IPv6 + UDP packet header."""
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x86\xdd"
        src_ip6 = socket.inet_pton(socket.AF_INET6, "fd00:1::2")
        dst_ip6 = socket.inet_pton(socket.AF_INET6, "fd00:3::2")
        # IPv6: 4 bytes ver/tc/flow, 2 bytes payload_len (60), 1 byte next_hdr (17), 1 byte hop_limit (64)
        ip6_hdr = struct.pack("!IHBB", 0x60000000, 60, 17, 64) + src_ip6 + dst_ip6
        udp_hdr = struct.pack("!HH", 55005, 55005)

        raw = eth + ip6_hdr + udp_hdr
        res = parse_packet_header(raw)
        assert res is not None
        s_ip, d_ip, s_port, d_port, proto, pkt_len = res
        assert s_ip == "fd00:1::2"
        assert d_ip == "fd00:3::2"
        assert s_port == 55005
        assert d_port == 55005
        assert proto == 17
        assert pkt_len == 100  # 40 header + 60 payload

    def test_parse_vlan_tagged_packet(self):
        """Parse 802.1Q VLAN tagged frame."""
        # 18 bytes Ethernet with 0x8100 VLAN tag
        eth_vlan = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x81\x00\x00\x64\x08\x00"
        src_ip = socket.inet_aton("172.16.0.5")
        dst_ip = socket.inet_aton("8.8.8.8")
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
                             0x45, 0x00, 84, 0x5555, 0x0000, 64, 1, 0x0000, src_ip, dst_ip)

        raw = eth_vlan + ip_hdr
        res = parse_packet_header(raw)
        assert res is not None
        s_ip, d_ip, s_port, d_port, proto, pkt_len = res
        assert s_ip == "172.16.0.5"
        assert d_ip == "8.8.8.8"
        assert proto == 1

    def test_invalid_short_packet(self):
        """Packets shorter than 14 bytes must return None."""
        assert parse_packet_header(b"\x00\x11\x22") is None


class TestFlowClassifierRecordPacket:
    """Test FlowClassifier.record_packet alias and active flow tracking."""

    def test_record_packet_alias(self):
        """record_packet should ingest metadata and allow classification."""
        import time
        classifier = FlowClassifier()
        fid = "udp:192.168.1.100:1.1.1.1:55005:53"

        now = time.time() * 1000.0
        # Ingest small UDP packets (DNS / VoIP pattern)
        for i in range(5):
            classifier.record_packet(fid, now + i * 20.0, 160, 17)

        active = classifier.get_active_flow_ids(active_within_ms=10000.0)
        assert fid in active

        label, conf, method = classifier.classify(fid)
        assert isinstance(label, int)
        assert 0 <= label <= 3
        assert 0.0 <= conf <= 1.0


class TestScenario4Setup:
    """Test Scenario 4 setup, asymmetric shaping, and worker initialization."""

    def test_swarm_transfer_worker_init(self):
        """SwarmTransferWorker should configure upload and download ports."""
        worker = SwarmTransferWorker(duration=5.0, upload_port=5201, download_port=5202)
        assert worker.upload_port == 5201
        assert worker.download_port == 5202
        assert "5201" in worker.upload_out
        assert "5202" in worker.download_out

    def test_asymmetric_shaping_rates(self):
        """TcEnforcer should support distinct upload and download rates."""
        enforcer = TcEnforcer()
        down_allocs = {0: 12.5, 1: 17.5, 2: 12.5, 3: 7.5}
        up_allocs = {0: 2.5, 1: 3.5, 2: 2.5, 3: 1.5}

        # Generate download batch (50 Mbps)
        batch_down = enforcer.generate_htb_batch("veth_rtr_lan", 50.0, down_allocs, headroom_factor=0.90)
        # Generate upload batch (10 Mbps)
        batch_up = enforcer.generate_htb_batch("veth_rtr_wan", 10.0, up_allocs, headroom_factor=0.90)

        assert "rate 45.00mbit" in batch_down  # 50 * 0.90 = 45 Mbps effective
        assert "rate 9.00mbit" in batch_up     # 10 * 0.90 = 9 Mbps effective

    def test_live_wifi_flow_metadata_and_class_name(self):
        """Live Wi-Fi daemon must correctly resolve human-readable class names and active intents without AttributeError."""
        from scripts.run_live_wifi import LiveWifiDaemon
        from src.policy.policy_engine import UserIntent

        intent = UserIntent(flow_id="test_flow", target_class=0, priority_boost=15.0, created_at=time.time(), ttl_seconds=60.0)
        assert not intent.expired
        assert not intent.is_expired

        daemon = LiveWifiDaemon(iface="lo", ifb="ifb0", wan_rate=30.0)
        assert daemon.classifier.get_class_name(0) == "realtime_voice"
        assert daemon.classifier.get_class_name(1) == "interactive_video"
        assert daemon.classifier.get_class_name(2) == "responsive_web"
        assert daemon.classifier.get_class_name(3) == "bulk_transfer"
        assert daemon.classifier.get_class_name(99) == "unknown"

        # Verify export state works with active intents
        daemon.policy.add_intent("test_flow", 0, 15.0, 60.0)
        daemon._export_state([], {0: 10.0, 1: 10.0, 2: 5.0, 3: 5.0})
        import json
        with open(daemon.state_file, "r") as f:
            data = json.load(f)
        assert len(data["active_intents"]) == 1
        assert data["active_intents"][0]["flow_id"] == "test_flow"


