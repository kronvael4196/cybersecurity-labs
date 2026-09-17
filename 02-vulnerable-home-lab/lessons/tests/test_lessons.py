import re
import unittest
from app import create_app


class LessonsTests(unittest.TestCase):
    def test_sqli_and_patch(self):
        for mode, expected in [("vulnerable", 2), ("hardened", 0)]:
            client = create_app(mode).test_client()
            result = client.get("/search", query_string={"q": "' OR 1=1 --"})
            self.assertEqual(len(result.json), expected)

    def test_xss_and_escape(self):
        payload = "<script>alert('lab')</script>"
        self.assertIn(payload.encode(), create_app("vulnerable").test_client().get("/echo", query_string={"message": payload}).data)
        response = create_app("hardened").test_client().get("/echo", query_string={"message": payload})
        self.assertNotIn(payload.encode(), response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertIn("Content-Security-Policy", response.headers)

    def test_csrf_and_valid_form(self):
        vulnerable = create_app("vulnerable").test_client()
        self.assertEqual(vulnerable.post("/profile", data={"email": "lab@example.test"}).status_code, 200)
        hardened = create_app("hardened").test_client()
        self.assertEqual(hardened.post("/profile", data={"email": "lab@example.test"}).status_code, 403)
        page = hardened.get("/").data.decode()
        token = re.search(r'name="csrf" value="([^"]+)"', page)[1]
        self.assertEqual(hardened.post("/profile", data={"email": "lab@example.test", "csrf": token}).status_code, 200)


if __name__ == "__main__":
    unittest.main()
