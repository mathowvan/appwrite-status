import json
import unittest
from unittest import mock

from src import main as handler
from src import status

class Req:
    def __init__(self, method="GET", path="/"):
        self.method, self.path = method, path
        # Sentinel inputs must never be read, logged, or reflected.
        self.headers = {"x-appwrite-key": "DO_NOT_LEAK_KEY"}
        self.bodyText = "DO_NOT_LEAK_BODY"
class Res:
    def text(self, body, code=200, headers=None):
        return (body, code, headers or {})
class Context:
    req, res = None, Res()
    def __init__(self, method="GET", path="/"):
        self.req = Req(method, path)

class RoutesTests(unittest.TestCase):
    @mock.patch.object(handler, "get_status", return_value={"runtime":{"python":"3.12","os":"Linux","architecture":"x86"},"process_uptime_seconds":4,"resources":{"cpu_limit_cores":1,"memory_limit":"128 MiB","mounted_root_disk":{"free":"1 GiB","total":"2 GiB"}},"tools":{"curl":{"installed":True,"version":"8.0"}},"scope":"temporary"})
    def test_root_html_headers_and_repository_link(self, _):
        body, code, headers = handler.main(Context())
        self.assertEqual(code, 200)
        self.assertEqual(headers["content-type"], "text/html; charset=utf-8")
        self.assertIn('href="https://github.com/mathowvan/appwrite-status"', body)
        self.assertIn("按需执行环境", body)
        self.assertIn("style-src 'unsafe-inline'", headers["content-security-policy"])

    @mock.patch.object(handler, "get_status", return_value={"x":"y"})
    def test_json(self, _):
        body, code, headers = handler.main(Context(path="/api/status"))
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"x":"y"})
        self.assertTrue(headers["content-type"].startswith("application/json"))

    def test_health_unknown_method_and_unknown_path(self):
        self.assertEqual(handler.main(Context(path="/healthz"))[:2], ("ok\n", 200))
        self.assertEqual(handler.main(Context(path="/other"))[:2], ("Not Found\n", 404))
        body, code, headers = handler.main(Context("POST", "/"))
        self.assertEqual((body, code), ("Method Not Allowed\n", 405))
        self.assertEqual(headers["allow"], "GET")

    @mock.patch.object(handler, "get_status", return_value={"runtime":{"python":"<script>alert(1)</script>","os":"Linux","architecture":"x86"},"process_uptime_seconds":1,"resources":{"cpu_limit_cores":None,"memory_limit":"不可用","mounted_root_disk":None},"tools":{},"scope":"safe"})
    def test_html_escapes_variable_content_and_never_exposes_request(self, _):
        body, _, _ = handler.main(Context())
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertNotIn("DO_NOT_LEAK_KEY", body)
        self.assertNotIn("DO_NOT_LEAK_BODY", body)
        self.assertNotIn("x-appwrite-key", body)

class FormattingAndProbeTests(unittest.TestCase):
    def test_binary_units_and_human_duration(self):
        self.assertEqual(status.format_bytes(1024), "1.0 KiB")
        self.assertEqual(status.format_bytes(1024**2), "1.0 MiB")
        self.assertEqual(status.format_duration(90061), "1天 1小时 1分钟 1秒")
        self.assertEqual(status.format_bytes(None), "不可用")

    @mock.patch("src.status.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("curl", .55))
    @mock.patch("src.status.shutil.which", return_value="/usr/bin/curl")
    def test_fixed_probe_timeout_is_bounded(self, _, run):
        result = status._probe("curl", ("--version",), r"^curl\s+([\w.+-]+)")
        self.assertEqual(result["version"], "探测超时或不可用")
        self.assertLessEqual(run.call_args.kwargs["timeout"], .55)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_probe_does_not_use_user_input_as_executable(self):
        with mock.patch("src.status.shutil.which", return_value=None) as which:
            self.assertFalse(status._probe("curl", ("--version",), "^curl")["installed"])
            which.assert_called_once_with("curl", path=status._FIXED_PATH)

if __name__ == "__main__":
    unittest.main()
