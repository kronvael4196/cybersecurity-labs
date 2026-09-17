import datetime
import unittest

from ssh.collector import event


class CollectorTests(unittest.TestCase):
    def test_keeps_original_message_and_utc_timestamp(self):
        message = "Failed password for invalid user admin from 192.0.2.1 port 40222 ssh2"
        record = event(message + "\n")
        self.assertEqual(record["message"], message)
        self.assertEqual(record["event"]["dataset"], "ssh.auth")
        self.assertEqual(datetime.datetime.fromisoformat(record["@timestamp"]).utcoffset(),
                         datetime.timedelta(0))

    def test_identical_messages_are_distinct_events(self):
        self.assertNotEqual(event("same")["event"]["id"], event("same")["event"]["id"])


if __name__ == "__main__":
    unittest.main()
