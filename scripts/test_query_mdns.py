import contextlib
import io
import socket
import struct
import unittest

from query_mdns import decode_dns_name, encode_dns_name, print_answers


class MdnsQueryTests(unittest.TestCase):
    def answer(self, name="gateway.local", ttl=30):
        header = struct.pack("!6H", 0, 0x8400, 0, 1, 0, 0)
        return header + encode_dns_name(name) + struct.pack("!HHIH", 1, 0x8001, ttl, 4) + socket.inet_aton("192.0.2.10")

    def test_unrelated_records_are_not_reported_as_the_requested_host(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            count = print_answers(self.answer("other.local"), ("192.0.2.10", 5353), "gateway.local")
        self.assertEqual(count, 0)
        self.assertEqual(output.getvalue(), "")

    def test_matching_records_accept_case_and_ignore_goodbyes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(print_answers(self.answer(), ("192.0.2.10", 5353), "Gateway.LOCAL."), 1)
            self.assertEqual(print_answers(self.answer(ttl=0), ("192.0.2.10", 5353), "gateway.local"), 0)

    def test_compressed_names_and_malformed_packets(self):
        name = encode_dns_name("gateway.local")
        self.assertEqual(decode_dns_name(name + b"\xc0\x00", len(name)), ("gateway.local", len(name) + 2))
        with self.assertRaises(ValueError):
            decode_dns_name(b"\xc0\x00", 0)
        self.assertEqual(print_answers(self.answer()[:-1], ("192.0.2.10", 5353), "gateway.local"), 0)


if __name__ == "__main__":
    unittest.main()
