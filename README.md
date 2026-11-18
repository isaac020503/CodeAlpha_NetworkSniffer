# CodeAlpha_NetworkSniffer

Basic network sniffer in Python (Scapy) for the CodeAlpha Cyber Security internship, Task 1.

## What it does
- Captures live packets from a network interface
- Shows timestamp, source/destination IP, protocol, ports, TCP flags and packet size
- Shows DNS queries and a short payload preview
- Prints a protocol summary when stopped
- Optionally saves the capture to a `.pcap` file (open it in Wireshark)

## Requirements
- Python 3.8+
- `pip install scapy`
- Windows: install [Npcap](https://npcap.com) and run the terminal as Administrator
- Linux/macOS: run with `sudo`

## Usage
```bash
sudo python3 sniffer.py                         # capture until Ctrl+C
sudo python3 sniffer.py -c 50                   # capture 50 packets
sudo python3 sniffer.py -f "tcp port 80"        # BPF filter
sudo python3 sniffer.py -i eth0 -o capture.pcap # pick interface, save pcap
```

## How it works
1. Scapy's `sniff()` reads raw frames from the interface.
2. Each packet is passed to `handle_packet()`, which walks the protocol layers (Ethernet, IP, TCP/UDP/ICMP, then Raw payload).
3. Layer fields are printed, and counters track protocol totals.

## What you learn
- Packet structure: headers vs payload
- How TCP, UDP, ICMP, ARP and DNS look on the wire
- Why unencrypted protocols (HTTP, FTP, Telnet) expose data and why HTTPS matters

## Ethics
Only capture traffic on networks you own or have explicit permission to monitor.
