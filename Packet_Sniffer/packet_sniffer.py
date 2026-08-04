#!/usr/bin/env python3
"""
Network Packet Capture & Analysis Tool
========================================

Educational tool for capturing and analyzing network packets using scapy.
Learn how data flows through the network by inspecting headers and payloads
for common protocols (Ethernet, IP, TCP, UDP, ICMP, DNS, ARP).

REQUIREMENTS:
    pip install scapy

USAGE:
    Must be run with elevated privileges (packet capture requires it).

    Linux/macOS:
        sudo python3 packet_sniffer.py
        sudo python3 packet_sniffer.py -i eth0 -c 50
        sudo python3 packet_sniffer.py -f "tcp port 80"

    Windows (run terminal as Administrator, Npcap must be installed):
        python packet_sniffer.py -i "Ethernet"

NOTE:
    This tool is intended for learning and for use on networks/devices you
    own or have explicit permission to monitor. Capturing traffic on
    networks you don't control or don't have authorization for may be
    illegal in your jurisdiction.
"""

import argparse
import datetime
import sys

try:
    from scapy.all import (
        sniff, get_if_list, conf,
        Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
    )
except ImportError:
    print("scapy is not installed. Install it with:\n    pip install scapy")
    sys.exit(1)


# ----------------------------------------------------------------------
# Packet counters (simple running stats, printed at the end)
# ----------------------------------------------------------------------
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "dns": 0,
    "other": 0,
}


def format_payload(raw_bytes, max_len=64):
    """Return a printable, truncated preview of raw payload bytes."""
    if not raw_bytes:
        return None
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = repr(raw_bytes)
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text


def describe_packet(pkt):
    """Build a human-readable summary dict for one captured packet."""
    info = {
        "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "length": len(pkt),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "proto": "OTHER",
        "src_port": None,
        "dst_port": None,
        "detail": "",
        "payload": None,
    }

    if Ether in pkt:
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    # --- ARP (no IP layer involved) ---
    if ARP in pkt:
        info["proto"] = "ARP"
        info["src_ip"] = pkt[ARP].psrc
        info["dst_ip"] = pkt[ARP].pdst
        op = "request" if pkt[ARP].op == 1 else "reply"
        info["detail"] = f"ARP {op}: who has {pkt[ARP].pdst}? tell {pkt[ARP].psrc}"
        stats["arp"] += 1
        return info

    # --- IPv4 / IPv6 ---
    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]

    if ip_layer is not None:
        info["src_ip"] = ip_layer.src
        info["dst_ip"] = ip_layer.dst

        if TCP in pkt:
            info["proto"] = "TCP"
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
            flags = pkt[TCP].flags
            info["detail"] = f"flags={flags}"
            stats["tcp"] += 1

            if pkt.haslayer(DNS):
                info["proto"] = "DNS/TCP"
                stats["dns"] += 1

        elif UDP in pkt:
            info["proto"] = "UDP"
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
            stats["udp"] += 1

            if pkt.haslayer(DNS):
                info["proto"] = "DNS"
                dns_layer = pkt[DNS]
                if dns_layer.qr == 0 and dns_layer.qd is not None:
                    qname = dns_layer.qd.qname.decode(errors="replace")
                    info["detail"] = f"query for {qname}"
                elif dns_layer.qr == 1:
                    info["detail"] = "response"
                stats["dns"] += 1

        elif ICMP in pkt:
            info["proto"] = "ICMP"
            icmp_types = {0: "echo-reply", 8: "echo-request"}
            info["detail"] = icmp_types.get(pkt[ICMP].type, f"type={pkt[ICMP].type}")
            stats["icmp"] += 1

        else:
            stats["other"] += 1
    else:
        stats["other"] += 1

    # --- Raw payload preview (application-layer data, if any) ---
    if Raw in pkt:
        info["payload"] = format_payload(bytes(pkt[Raw].load))

    return info


def print_packet(pkt):
    """Callback invoked by scapy for each captured packet."""
    stats["total"] += 1
    info = describe_packet(pkt)

    header = f"[{info['time']}] #{stats['total']:<4} {info['proto']:<8} len={info['length']}"

    if info["src_ip"]:
        addr = f"{info['src_ip']}"
        if info["src_port"]:
            addr += f":{info['src_port']}"
        addr += " -> "
        addr += f"{info['dst_ip']}"
        if info["dst_port"]:
            addr += f":{info['dst_port']}"
    elif info["src_mac"]:
        addr = f"{info['src_mac']} -> {info['dst_mac']}"
    else:
        addr = "n/a"

    line = f"{header}  {addr}"
    if info["detail"]:
        line += f"  ({info['detail']})"
    print(line)

    if info["payload"]:
        print(f"        payload: {info['payload']}")


def print_summary():
    print("\n" + "=" * 50)
    print("Capture summary")
    print("=" * 50)
    print(f"Total packets : {stats['total']}")
    print(f"  TCP         : {stats['tcp']}")
    print(f"  UDP         : {stats['udp']}")
    print(f"  ICMP        : {stats['icmp']}")
    print(f"  ARP         : {stats['arp']}")
    print(f"  DNS         : {stats['dns']}")
    print(f"  Other       : {stats['other']}")


def main():
    parser = argparse.ArgumentParser(
        description="Capture and analyze network packets using scapy."
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to sniff on (default: scapy's chosen default)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (0 = capture until Ctrl+C)"
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help='BPF filter string, e.g. "tcp port 80" or "udp port 53"'
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List available network interfaces and exit"
    )
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  {iface}")
        return

    print("Starting packet capture...")
    print(f"Interface : {args.interface or conf.iface}")
    print(f"Filter    : {args.filter or '(none)'}")
    print(f"Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 50)

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=print_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print("\nPermission denied. Run this script with sudo/administrator privileges.")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()


if __name__ == "__main__":
    main()