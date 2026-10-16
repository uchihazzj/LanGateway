"""Send an mDNS A-record query and print any responses.

Usage:
    python scripts/query_mdns.py [hostname]

Default hostname is gateway.local.
Uses a UDP socket to send a valid mDNS query to 224.0.0.251:5353.
Sets the unicast-response (QU) bit so responders reply directly.
"""

import argparse
import socket
import struct
import sys
import time

MDNS_MULTICAST = "224.0.0.251"
MDNS_PORT = 5353


def encode_dns_name(name: str) -> bytes:
    """Encode a dotted name into DNS label format."""
    buf = bytearray()
    name = name.rstrip(".")
    for label in name.split("."):
        buf.append(len(label))
        buf.extend(label.encode("ascii"))
    buf.append(0)
    return bytes(buf)


def build_query(hostname: str) -> bytes:
    """Build an mDNS A-record query for `hostname`."""
    tx_id = b"\x00\x00"
    flags = b"\x00\x00"
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    qname = encode_dns_name(hostname)
    qtype = b"\x00\x01"
    qclass = b"\x80\x01"
    return tx_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass


def decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a bounded, possibly compressed name without following cycles."""
    labels = []
    visited = set()
    end = None
    name_size = 1
    while offset < len(data) and offset not in visited:
        visited.add(offset)
        label_len = data[offset]
        if label_len & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                break
            if end is None:
                end = offset + 2
            offset = struct.unpack_from("!H", data, offset)[0] & 0x3FFF
            continue
        if label_len == 0:
            return ".".join(labels), end if end is not None else offset + 1
        if label_len & 0xC0 or offset + 1 + label_len > len(data):
            break
        name_size += 1 + label_len
        if name_size > 255:
            break
        labels.append(data[offset + 1 : offset + 1 + label_len].decode("ascii"))
        offset += 1 + label_len
    raise ValueError("Malformed DNS name")


def print_answers(data: bytes, addr: tuple[str, int], hostname: str) -> int:
    """Print only matching, live IN address records; return their count."""
    if len(data) < 12:
        return 0
    flags = struct.unpack_from("!H", data, 2)[0]
    qr = (flags >> 15) & 1
    qdcount = struct.unpack_from("!H", data, 4)[0]
    ancount = struct.unpack_from("!H", data, 6)[0]
    if qr != 1 or flags & 0x780F or ancount == 0:
        return 0

    offset = 12
    for _ in range(qdcount):
        try:
            _, offset = decode_dns_name(data, offset)
        except (ValueError, UnicodeError):
            return 0
        if offset + 4 > len(data):
            return 0
        offset += 4

    matches = 0
    for _ in range(ancount):
        try:
            answer_name, offset = decode_dns_name(data, offset)
        except (ValueError, UnicodeError):
            break
        if offset + 10 > len(data):
            break
        rtype = struct.unpack_from("!H", data, offset)[0]
        rclass = struct.unpack_from("!H", data, offset + 2)[0] & 0x7FFF
        ttl = struct.unpack_from("!I", data, offset + 4)[0]
        rdlen = struct.unpack_from("!H", data, offset + 8)[0]
        offset += 10
        if offset + rdlen > len(data):
            break

        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if answer_name.lower() != hostname.rstrip(".").lower() or rclass != 1 or ttl == 0:
            continue
        if rtype == 1 and rdlen == 4:
            ip = socket.inet_ntop(socket.AF_INET, rdata)
            print(f"  Response from {addr[0]}:{addr[1]} - {hostname} -> {ip} (TTL={ttl})")
            matches += 1
        elif rtype == 28 and rdlen == 16:
            ip6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(
                f"  Response from {addr[0]}:{addr[1]} - {hostname} -> {ip6} "
                f"(AAAA, TTL={ttl})"
            )
            matches += 1
    return matches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hostname", nargs="?", default="gateway.local")
    parser.add_argument("--interface", help="Local IPv4 address of the client adapter to use, useful with VPNs")
    args = parser.parse_args()
    hostname = args.hostname
    print(f"Sending mDNS A query for {hostname} to {MDNS_MULTICAST}:{MDNS_PORT}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(3.0)
    if args.interface:
        interface = socket.inet_aton(args.interface)
        sock.bind((args.interface, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, interface)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

    query = build_query(hostname)
    sock.sendto(query, (MDNS_MULTICAST, MDNS_PORT))
    print(f"Sent {len(query)} bytes")

    deadline = time.monotonic() + 5.0
    matches = 0
    while time.monotonic() < deadline:
        sock.settimeout(max(0.01, deadline - time.monotonic()))
        try:
            data, addr = sock.recvfrom(1500)
            matches += print_answers(data, addr, hostname)
        except socket.timeout:
            break

    sock.close()
    if not matches:
        print("No matching address record received. Check the hostname, client adapter, server firewall and multicast reachability.")
        return 1
    print(f"Done: {matches} matching address record(s). This does not verify the browser's resolver or the service port.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
