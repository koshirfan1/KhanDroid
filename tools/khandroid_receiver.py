#!/usr/bin/env python3
"""
KhanDroid UDP receiver.

Listens for UDP datagrams sent by KhanDroid's UdpExporter (each datagram =
16-byte pcap-record header + one raw IPv4 packet) and writes them into a
.pcap file that Wireshark can open.

Usage:
    python3 khandroid_receiver.py [output.pcap] [--port 5555]
"""
import argparse
import socket
import struct
import sys

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_RAW = 101  # TUN interface gives us raw IP, no Ethernet header


def main():
    parser = argparse.ArgumentParser(description="KhanDroid UDP -> pcap receiver")
    parser.add_argument("output", nargs="?", default="capture.pcap",
                         help="output .pcap file (default: capture.pcap)")
    parser.add_argument("--host", default="0.0.0.0", help="bind address")
    parser.add_argument("--port", type=int, default=5555, help="UDP port (must match app config)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print(f"[khandroid] listening on udp {args.host}:{args.port}, writing to {args.output}")
    print("[khandroid] open the file in Wireshark; re-open it to refresh while capturing")

    packet_count = 0
    with open(args.output, "wb") as f:
        # Global pcap header, written once.
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        f.flush()

        try:
            while True:
                data, addr = sock.recvfrom(70000)
                if len(data) < 16:
                    continue  # malformed/short datagram, skip
                f.write(data)
                f.flush()
                packet_count += 1
                if packet_count % 50 == 0:
                    print(f"[khandroid] {packet_count} packets written (last from {addr[0]})")
        except KeyboardInterrupt:
            print(f"\n[khandroid] stopped. {packet_count} packets written to {args.output}")
            sys.exit(0)


if __name__ == "__main__":
    main()
