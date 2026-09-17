import unittest
from analyze import summarize


class AnalyzeTests(unittest.TestCase):
    def test_http_and_encrypted_protocols(self):
        text = ('1\t100\t10.77.0.2\t172.30.78.10\t\t\tHTTP\t8080\t\tGET\tprivate.test\n'
                '2\t80\t172.30.77.3\t172.30.77.2\t\t\tWireGuard\t\t51820\t\t\n')
        report = summarize(text)
        self.assertEqual(report["packet_count"], 2)
        self.assertEqual(report["captured_bytes"], 180)
        self.assertEqual(report["protocols"]["WireGuard"], 1)
        self.assertEqual(len(report["cleartext_http"]), 1)

    def test_empty_capture(self):
        self.assertEqual(summarize("")["packet_count"], 0)

    def test_ipv6(self):
        report = summarize('1\t60\t\t\t::1\t::1\tTCP\t80\t\t\t\n')
        self.assertEqual(report["connections"][0]["source"], "::1")


if __name__ == "__main__":
    unittest.main()
