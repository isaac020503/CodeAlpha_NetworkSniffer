#!/usr/bin/env python3
"""
CodeAlpha_NetworkSniffer
Basic network sniffer built with Scapy.

Captures packets on your own network interface and prints:
  - timestamp, source/destination IP, protocol
  - ports (TCP/UDP), TCP flags
  - a short payload preview
Optionally saves the capture to a .pcap file for Wireshark.

Run only on networks you own or have permission to monitor.

Usage examples (needs admin/root):
  sudo python3 sniffer.py
  sudo python3 sniffer.py -c 50
  sudo python3 sniffer.py -f "tcp port 80" -o capture.pcap
  sudo python3 sniffer.py -i eth0 -f "udp port 53"
"""

import argparse
import sys
from datetime import datetime
from collections import Counter

try:
    from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR
except ImportError:
    sys.exit("Scapy is not installed. Run: pip install scapy")

stats = Counter()
captured = []


def payload_preview(packet, limit=60):
    """Return a printable preview of the packet payload."""
    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)[:limit]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return text
    return ""


def handle_packet(packet):
    captured.append(packet)
    ts = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(ARP):
        stats["ARP"] += 1
        arp = packet[ARP]
        op = "request" if arp.op == 1 else "reply"
        print(f"[{ts}] ARP {op}: {arp.psrc} -> {arp.pdst}")
        return

    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
    else:
        stats["Other"] += 1
        return

    if packet.haslayer(TCP):
        proto = "TCP"
        l4 = packet[TCP]
        detail = f"{src}:{l4.sport} -> {dst}:{l4.dport} flags={l4.flags}"
    elif packet.haslayer(UDP):
        proto = "UDP"
        l4 = packet[UDP]
        detail = f"{src}:{l4.sport} -> {dst}:{l4.dport}"
    elif packet.haslayer(ICMP):
        proto = "ICMP"
        detail = f"{src} -> {dst} type={packet[ICMP].type}"
    else:
        proto = "IP"
        detail = f"{src} -> {dst}"

    stats[proto] += 1
    print(f"[{ts}] {proto:<4} {detail} len={len(packet)}")

    if packet.haslayer(DNSQR) and packet.haslayer(DNS):
        qname = packet[DNSQR].qname.decode(errors="ignore")
        kind = "response" if packet[DNS].qr == 1 else "query"
        print(f"        DNS {kind}: {qname}")

    preview = payload_preview(packet)
    if preview:
        print(f"        payload: {preview}")


def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer (CodeAlpha)")
    parser.add_argument("-i", "--interface", help="Interface to sniff on (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80'")
    parser.add_argument("-o", "--output", help="Save capture to this .pcap file")
    args = parser.parse_args()

    print("Starting capture... press Ctrl+C to stop.\n")
    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=handle_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        sys.exit("Permission denied. Run as administrator/root.")
    except KeyboardInterrupt:
        pass

    print("\n--- Summary ---")
    print(f"Total packets: {len(captured)}")
    for proto, n in stats.most_common():
        print(f"  {proto}: {n}")

    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"Saved capture to {args.output}")


if __name__ == "__main__":
    main()
