"""Send an mDNS A-record query and print any responses.

Usage:
    python scripts/query_mdns.py [hostname]

Default hostname is gateway.local.
Uses raw sockets to send a valid mDNS query to 224.0.0.251:5353.
Sets the unicast-response (QU) bit so responders reply directly.
"""

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


def skip_dns_name(data: bytes, offset: int) -> int:
    """Skip a DNS name at `offset`, handling compression pointers."""
    while offset < len(data):
        label_len = data[offset]
        if label_len & 0xC0 == 0xC0:
            return offset + 2
        if label_len == 0:
            return offset + 1
        offset += 1 + label_len
    return offset


def print_answers(data: bytes, addr: tuple[str, int], hostname: str) -> None:
    """Print A and AAAA answers from an mDNS response packet."""
    if len(data) < 12:
        return
    flags = struct.unpack_from("!H", data, 2)[0]
    qr = (flags >> 15) & 1
    qdcount = struct.unpack_from("!H", data, 4)[0]
    ancount = struct.unpack_from("!H", data, 6)[0]
    if qr != 1 or ancount == 0:
        return

    offset = 12
    for _ in range(qdcount):
        offset = skip_dns_name(data, offset)
        offset += 4

    for _ in range(ancount):
        offset = skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype = struct.unpack_from("!H", data, offset)[0]
        ttl = struct.unpack_from("!I", data, offset + 4)[0]
        rdlen = struct.unpack_from("!H", data, offset + 8)[0]
        offset += 10
        if offset + rdlen > len(data):
            break

        rdata = data[offset : offset + rdlen]
        if rtype == 1 and rdlen == 4:
            ip = socket.inet_ntop(socket.AF_INET, rdata)
            print(f"  Response from {addr[0]}:{addr[1]} - {hostname} -> {ip} (TTL={ttl})")
        elif rtype == 28 and rdlen == 16:
            ip6 = socket.inet_ntop(socket.AF_INET6, rdata)
            print(
                f"  Response from {addr[0]}:{addr[1]} - {hostname} -> {ip6} "
                f"(AAAA, TTL={ttl})"
            )
        offset += rdlen


def main() -> None:
    hostname = sys.argv[1] if len(sys.argv) > 1 else "gateway.local"
    print(f"Sending mDNS A query for {hostname} to {MDNS_MULTICAST}:{MDNS_PORT}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(3.0)

    query = build_query(hostname)
    sock.sendto(query, (MDNS_MULTICAST, MDNS_PORT))
    print(f"Sent {len(query)} bytes")

    start = time.time()
    while time.time() - start < 5.0:
        try:
            data, addr = sock.recvfrom(1500)
            print_answers(data, addr, hostname)
        except socket.timeout:
            break

    sock.close()
    print("Done.")


if __name__ == "__main__":
    main()
