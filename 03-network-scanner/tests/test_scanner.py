import socket
import threading
import unittest
from scanner import parse_ports, parse_targets, report_html, scan_port


class ScannerTests(unittest.TestCase):
    def test_ports_ranges_and_validation(self):
        self.assertEqual(parse_ports("80,22,80,443-444"), [22, 80, 443, 444])
        for value in ("0", "65536", "90-80", "1-2-3"):
            with self.assertRaises(ValueError):
                parse_ports(value)

    def test_scope_and_size(self):
        self.assertEqual(parse_targets("127.0.0.1", ["127.0.0.0/8"]), ["127.0.0.1"])
        self.assertEqual(parse_targets("::1", ["::1/128"]), ["::1"])
        for value in ("10.0.0.1", "127.0.0.0/8"):
            with self.assertRaises(ValueError):
                parse_targets(value, ["127.0.0.0/8"])

    def test_real_local_connection_and_banner(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            def send():
                conn, _ = server.accept()
                with conn:
                    conn.sendall(b"SSH-2.0-Lab\r\n")
            thread = threading.Thread(target=send, daemon=True)
            thread.start()
            result = scan_port("127.0.0.1", server.getsockname()[1], 1, True)
            thread.join(2)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["service"], "ssh")

    def test_html_escapes_untrusted_banners(self):
        report = {"results": [{"ip": "127.0.0.1", "port": 22, "state": "open",
                  "service": "ssh", "service_hint": "ssh", "banner": "<script>bad()</script>", "findings": []}]}
        self.assertNotIn("<script>", report_html(report))
        self.assertIn("&lt;script&gt;", report_html(report))


if __name__ == "__main__":
    unittest.main()
