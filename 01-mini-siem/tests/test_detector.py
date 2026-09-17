import datetime as dt
import unittest
from unittest.mock import patch

from siem.app import candidates, detect_once, positive_setting, should_alert, window_query


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)

    def test_threshold_and_cooldown_boundaries(self):
        self.assertFalse(should_alert(4, 5, self.now, None, 120))
        self.assertTrue(should_alert(5, 5, self.now, None, 120))
        self.assertFalse(should_alert(8, 5, self.now, self.now - dt.timedelta(seconds=119), 120))
        self.assertTrue(should_alert(8, 5, self.now, self.now - dt.timedelta(seconds=120), 120))

    def test_window_excludes_successes_and_future_events(self):
        filters = window_query(self.now, 60)["bool"]["filter"]
        self.assertIn({"term": {"event.outcome": "failure"}}, filters)
        bounds = filters[2]["range"]["@timestamp"]
        self.assertEqual(dt.datetime.fromisoformat(bounds["lte"]), self.now)
        self.assertEqual(dt.datetime.fromisoformat(bounds["gte"]), self.now - dt.timedelta(seconds=60))

    @patch("siem.app.request")
    def test_paginates_ips(self, request):
        request.side_effect = [
            {"aggregations": {"ips": {"buckets": [{"key": {"ip": "192.0.2.1"}, "doc_count": 5}],
                                       "after_key": {"ip": "192.0.2.1"}}}},
            {"aggregations": {"ips": {"buckets": []}}},
        ]
        self.assertEqual(len(list(candidates(self.now, 60))), 1)
        self.assertEqual(request.call_args.args[1]["aggs"]["ips"]["composite"]["after"], {"ip": "192.0.2.1"})

    @patch("siem.app.request")
    @patch("siem.app.candidates")
    def test_alerts_only_for_qualifying_ip(self, candidates_mock, request):
        candidates_mock.return_value = [
            {"key": {"ip": "192.0.2.1"}, "doc_count": 4},
            {"key": {"ip": "192.0.2.2"}, "doc_count": 5},
        ]
        request.side_effect = [{"hits": {"hits": []}}, {"result": "created"}]
        detect_once(5, 60, 120)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args.args[1]["source"]["ip"], "192.0.2.2")

    @patch("siem.app.request")
    @patch("siem.app.candidates")
    def test_persisted_alert_suppresses_after_restart(self, candidates_mock, request):
        candidates_mock.return_value = [{"key": {"ip": "192.0.2.1"}, "doc_count": 8}]
        request.return_value = {"hits": {"hits": [{"_source": {
            "@timestamp": dt.datetime.now(dt.timezone.utc).isoformat()}}]}}
        detect_once(5, 60, 120)
        self.assertEqual(request.call_count, 1)

    @patch.dict("os.environ", {"FAILURE_THRESHOLD": "0"})
    def test_rejects_invalid_settings(self):
        with self.assertRaises(ValueError):
            positive_setting("FAILURE_THRESHOLD", "5")


if __name__ == "__main__":
    unittest.main()
