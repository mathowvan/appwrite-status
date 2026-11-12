import json
import math
import subprocess
import socket
import unittest
from unittest import mock

from src import main as handler
from src import status


def network_fixture():
    return {"scope": "local_only: current network namespace; not public egress or inbound reachability", "local_status": "available",
            "external_queries": False, "note": "local read-only ioctl and /proc/net data only; no external queries",
            "interfaces": [{"name": "eth0", "source": "current network namespace", "ipv4": "192.0.2.10", "ipv4_prefix_length": 24,
                            "ipv6": ["2001:db8::10"], "mtu": 1500, "admin_up": True, "running": True,
                            "counters": {"rx_bytes": 1024, "tx_bytes": 2048, "rx_packets": 5, "tx_packets": 3,
                                         "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0}}],
            "default_ipv4_gateway": {"ipv4": "192.0.2.1", "interface": "eth0"}}


class NoExternalNetworkMixin:
    def setUp(self):
        patcher = mock.patch.object(status, "collect_network", side_effect=network_fixture)
        patcher.start()
        self.addCleanup(patcher.stop)


class Req:
    def __init__(self, method="GET", path="/"):
        self.method, self.path = method, path
        self.headers = {"x-appwrite-key": "DO_NOT_LEAK_KEY"}
        self.bodyText = "DO_NOT_LEAK_BODY"


class Res:
    def text(self, body, code=200, headers=None):
        return body, code, headers or {}


class Context:
    res = Res()

    def __init__(self, method="GET", path="/"):
        self.req = Req(method, path)


def fixture():
    return {"runtime": {"python": "3.12", "implementation": "CPython", "python_bits": 64,
                         "byteorder": "little", "os": "Linux", "architecture": "x86", "openssl": "OpenSSL"},
            "module_age_seconds": 4, "snapshot_utc": "2026-01-01T00:00:00+00:00", "collection_seconds": .1,
            "cache_seconds": 30, "resources": {"cpu_limit_cores": 1,
            "memory_limit": "128 MiB", "memory": {"current_bytes": 1024, "peak_bytes": 2048,
            "limit_bytes": 4096, "percent": 25, "remaining_bytes": 3072},
            "mounted_root_disk": {"free": "1 GiB", "available": "1 GiB", "used": "1 GiB", "total": "2 GiB",
                                   "usage_percent": 50, "inode_total": 10, "inode_available": 5},
            "cgroup_cpu_stat": {"usage_seconds": 2, "user_seconds": 1, "system_seconds": 1,
                                "periods": 8, "throttled_periods": 3, "throttled_seconds": .1},
            "process": {"cpu_user_seconds": .001, "cpu_system_seconds": .002, "max_rss_bytes": 1024,
                        "proc_status_bytes_or_count": {"VmRSS": 10240, "VmHWM": 20480, "VmSize": 40960, "Threads": 2}},
            "swap": None}, "tools": {"curl": {"installed": True, "version": "8.0"}}, "scope": "temporary", "network": network_fixture()}


class RoutesTests(NoExternalNetworkMixin, unittest.TestCase):
    @mock.patch.object(handler, "get_status", return_value=fixture())
    def test_root_html_headers_layout_and_repo_link(self, _):
        body, code, headers = handler.main(Context())
        self.assertEqual(code, 200)
        self.assertEqual(headers["content-type"], "text/html; charset=utf-8")
        self.assertIn('href="https://github.com/mathowvan/appwrite-status"', body)
        self.assertIn("按需执行环境", body)
        self.assertIn("style-src 'unsafe-inline'", headers["content-security-policy"])
        self.assertEqual(body.count('<article class="card">'), 6)
        self.assertIn("--bg:#0b0d17", body)
        self.assertIn("grid-template-columns:repeat(3,minmax(0,1fr))", body)
        self.assertIn("@media(max-width:560px)", body)
        self.assertIn("本页不轮询、不保活", body)
        self.assertNotIn("<script", body.lower())
        self.assertNotIn('http-equiv="refresh"', body.lower())
        self.assertEqual(body.count("<style>"), 1)
        self.assertEqual(body.count("</style>"), 1)
        self.assertTrue(body.split("<style>")[1].lstrip().startswith(":root{"))
        self.assertIn("--panel:#111b2a", body)
        for label in ("VmRSS 常驻内存", "VmHWM 常驻峰值", "VmSize 虚拟地址空间（非物理内存）",
                      "进程 maxRSS 峰值", "用户态累计 CPU", "内核态累计 CPU", "节流累计时间",
                      "容量使用率", "inode 可用数（f_favail）"):
            self.assertIn(label, body)
        self.assertNotIn("{'usage_bytes'", body)

    @mock.patch.object(handler, "get_status", return_value={"x": "y"})
    def test_json(self, _):
        body, code, headers = handler.main(Context(path="/api/status"))
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), {"x": "y"})
        self.assertTrue(headers["content-type"].startswith("application/json"))

    def test_health_methods_and_unknown_path(self):
        self.assertEqual(handler.main(Context(path="/healthz"))[:2], ("ok\n", 200))
        self.assertEqual(handler.main(Context(path="/other"))[:2], ("Not Found\n", 404))
        body, code, headers = handler.main(Context("POST", "/"))
        self.assertEqual((body, code), ("Method Not Allowed\n", 405))
        self.assertEqual(headers["allow"], "GET")

    @mock.patch.object(handler, "get_status", return_value={**fixture(), "runtime": {**fixture()["runtime"], "python": "<script>alert(1)</script>"}, "scope": "<img src=x>"})
    def test_html_escaping_privacy_and_csp(self, _):
        body, _, headers = handler.main(Context())
        self.assertNotIn("<script>alert", body)
        self.assertNotIn("<img src=x>", body)
        for secret in ("DO_NOT_LEAK_KEY", "DO_NOT_LEAK_BODY", "x-appwrite-key"):
            self.assertNotIn(secret, body)
        self.assertIn("default-src 'none'", headers["content-security-policy"])

    def test_missing_new_fields_omitted_and_html_values_escaped(self):
        data = fixture()
        data["resources"] = {"memory": {"current_bytes": None}, "mounted_root_disk": {}, "process": None}
        body = status.render_page(data)
        self.assertNotIn("None", body)
        self.assertNotIn("VmRSS 常驻内存", body)
        self.assertNotIn("容量使用率", body)
        self.assertEqual(body.count('<article class="card">'), 6)


class MetricsTests(NoExternalNetworkMixin, unittest.TestCase):
    def test_scope_gate_requires_fixed_proc_membership_root(self):
        for value in ("0::/tenant/abc", "0::/", "1:memory:/", "2:cpu,cpuacct:/", "2:cpu,cpuacct:/nested"):
            with self.subTest(value=value), mock.patch.object(status, "_read", return_value=value):
                expected = "v2" if value == "0::/" else None
                self.assertEqual(status._cgroup_scope(), expected)
        text = "4:memory:/\n3:cpu,cpuacct:/\n"
        with mock.patch.object(status, "_read", return_value=text):
            self.assertEqual(status._cgroup_scope(), "v1")

    def test_v2_memory_zero_invalid_unlimited_and_excess(self):
        files = {"/proc/self/cgroup": "0::/", "/sys/fs/cgroup/memory.current": "0",
                 "/sys/fs/cgroup/memory.peak": "0", "/sys/fs/cgroup/memory.max": "100"}
        with mock.patch.object(status, "_read", side_effect=lambda p: files.get(p)):
            self.assertEqual(status._memory_stats(), {"current_bytes": 0, "peak_bytes": 0, "limit_bytes": 100, "percent": 0.0, "remaining_bytes": 100})
        files["/sys/fs/cgroup/memory.max"] = "0"
        with mock.patch.object(status, "_read", side_effect=lambda p: files.get(p)):
            self.assertIsNone(status._memory_stats()["limit_bytes"])
        files["/sys/fs/cgroup/memory.max"] = str(2**60)
        with mock.patch.object(status, "_read", side_effect=lambda p: files.get(p)):
            self.assertIsNone(status._memory_stats()["limit_bytes"])
        files.update({"/sys/fs/cgroup/memory.max": "100", "/sys/fs/cgroup/memory.current": "101"})
        with mock.patch.object(status, "_read", side_effect=lambda p: files.get(p)):
            self.assertIsNone(status._memory_stats()["percent"])
            self.assertIsNone(status._memory_stats()["remaining_bytes"])

    def test_v1_memory_and_cpu_stats(self):
        files = {"/proc/self/cgroup": "5:memory:/\n4:cpu,cpuacct:/", "/sys/fs/cgroup/memory/memory.usage_in_bytes": "80",
                 "/sys/fs/cgroup/memory/memory.max_usage_in_bytes": "90", "/sys/fs/cgroup/memory/memory.limit_in_bytes": "100",
                 "/sys/fs/cgroup/cpuacct/cpuacct.usage": "2500000000", "/sys/fs/cgroup/cpu/cpu.stat": "nr_periods 12\nnr_throttled 3"}
        with mock.patch.object(status, "_read", side_effect=lambda p: files.get(p)):
            self.assertEqual(status._memory_stats()["percent"], 80.0)
            self.assertEqual(status._cpu_stats(), {"usage_seconds": 2.5, "periods": 12, "throttled_periods": 3})

    def test_v1_cpu_quota_fixed_paths_only(self):
        files = {"/proc/self/cgroup": "1:memory:/\n2:cpu,cpuacct:/", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "50000",
                 "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000"}
        with mock.patch.object(status, "_read", side_effect=lambda p: files.get(p)):
            self.assertEqual(status._cpu_limit(), .5)

    def test_no_detailed_cgroup_metrics_without_verified_scope(self):
        with mock.patch.object(status, "_read", side_effect=lambda p: "0::/nested" if p == "/proc/self/cgroup" else "100"):
            self.assertEqual(status._memory_stats()["current_bytes"], None)
            self.assertIsNone(status._cpu_limit())
            self.assertIsNone(status._swap_stats())
            self.assertIsNone(status._cpu_stats())

    def test_swap_only_v2_finite_and_v1_never_read(self):
        with mock.patch.object(status, "_read", side_effect=lambda p: {"/proc/self/cgroup": "5:memory:/", "/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes": "100"}.get(p)):
            self.assertIsNone(status._swap_stats())
        vals = {"/proc/self/cgroup": "0::/", "/sys/fs/cgroup/memory.swap.current": "0", "/sys/fs/cgroup/memory.swap.max": "0"}
        with mock.patch.object(status, "_read", side_effect=lambda p: vals.get(p)):
            self.assertEqual(status._swap_stats(), {"usage_bytes": 0, "limit_bytes": 0, "percent": None})
        vals["/sys/fs/cgroup/memory.swap.max"] = "max"
        with mock.patch.object(status, "_read", side_effect=lambda p: vals.get(p)):
            self.assertIsNone(status._swap_stats())

    def test_cpu_v2_fields_convert_to_seconds(self):
        lines = "usage_usec 1234567\nuser_usec 80\nsystem_usec 43\nnr_periods 2\nnr_throttled 1\nthrottled_usec -1"
        def reader(path):
            return "0::/" if path == "/proc/self/cgroup" else lines if path == "/sys/fs/cgroup/cpu.stat" else None
        with mock.patch.object(status, "_read", side_effect=reader):
            self.assertEqual(status._cpu_stats(), {"usage_seconds": 1.234567, "user_seconds": .00008,
                                                   "system_seconds": .000043, "periods": 2, "throttled_periods": 1})

    def test_proc_status_allowlist(self):
        content = "Name:\tsecret\nVmRSS:\t10 kB\nVmHWM:\t12 kB\nVmSize:\t30 kB\nThreads:\t2\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=content)), mock.patch.object(status.resource, "getrusage", side_effect=OSError):
            data = status._process_stats()
        self.assertEqual(data["proc_status_bytes_or_count"], {"VmRSS": 10240, "VmHWM": 12288, "VmSize": 30720, "Threads": 2})
        self.assertNotIn("Name", str(data))

    def test_disk_capacity_and_inode_independent(self):
        usage = type("DU", (), {"total": 100, "used": 40, "free": 60})()
        statvfs = type("ST", (), {"f_files": 20, "f_favail": 5, "f_ffree": 8})()
        with mock.patch.object(status.shutil, "disk_usage", return_value=usage), mock.patch.object(status.os, "statvfs", return_value=statvfs), \
             mock.patch.object(status, "_probe", return_value={"installed": False, "version": None}):
            result = status._collect()["resources"]["mounted_root_disk"]
        self.assertEqual(result["usage_percent"], 40.0)
        self.assertEqual(result["inode_available"], 5)
        self.assertNotIn("inode_free", result)

    def test_formatting_nonfinite_and_short_durations(self):
        for value in (float("nan"), float("inf"), -1):
            self.assertEqual(status.format_bytes(value), "不可用")
        self.assertIn("毫秒", status.format_duration(.001))
        self.assertIn("秒", status.format_duration(1.2))
        self.assertIn("分钟", status.format_duration(60))

    def test_subprocess_only_fixed_allowlist_and_flags(self):
        with mock.patch.object(status, "_probe", return_value={"installed": False, "version": None}), \
             mock.patch.object(status.subprocess, "run", wraps=subprocess.run) as run:
            status._collect()
        run.assert_not_called()  # No hidden subprocess from runtime introspection.

    def test_cache_expiry(self):
        values = iter((100.0, 101.0, 102.0, 132.0, 133.0))
        with mock.patch.object(status, "_cache_value", None), mock.patch.object(status, "_collect", side_effect=[{"n": 1}, {"n": 2}]) as collect, \
             mock.patch.object(status.time, "monotonic", side_effect=lambda: next(values)), mock.patch.object(status, "_cache_at", 0):
            self.assertEqual(status.get_status(), {"n": 1})
            self.assertEqual(status.get_status(), {"n": 1})
            self.assertEqual(status.get_status(), {"n": 2})
        self.assertEqual(collect.call_count, 2)


class AdditionalRegressionTests(NoExternalNetworkMixin, unittest.TestCase):
    def test_probe_timeout_and_fixed_execution_environment(self):
        with mock.patch.object(status.shutil, "which", return_value="/usr/bin/curl"), mock.patch.object(status.subprocess, "run", side_effect=subprocess.TimeoutExpired("curl", .55)) as run:
            self.assertEqual(status._probe("curl", ("--version",), r"^curl\s+([\w.+-]+)")["version"], "探测超时或不可用")
        self.assertEqual(run.call_args.args[0], ["/usr/bin/curl", "--version"])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertLessEqual(run.call_args.kwargs["timeout"], .55)
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": status._FIXED_PATH, "LANG": "C", "LC_ALL": "C"})

    def test_probe_missing_and_version_output_is_allowlisted(self):
        with mock.patch.object(status.shutil, "which", return_value=None) as which:
            self.assertEqual(status._probe("curl", ("--version",), "^curl"), {"installed": False, "version": None})
            which.assert_called_once_with("curl", path=status._FIXED_PATH)
        fake = subprocess.CompletedProcess([], 0, b"curl 8.1.0 secret-unrelated-output\n")
        with mock.patch.object(status.shutil, "which", return_value="/usr/bin/curl"), mock.patch.object(status.subprocess, "run", return_value=fake):
            self.assertEqual(status._probe("curl", ("--version",), r"^curl\s+([\w.+-]+)"), {"installed": True, "version": "8.1.0"})

    def test_cpu_invalid_and_unlimited_never_report_finite_quota(self):
        for raw in ("max 100000", "-1 100000", "0 100000", "100000 0", "nan 100000", "", None):
            with self.subTest(raw=raw), mock.patch.object(status, "_cgroup_scope", return_value="v2"), mock.patch.object(status, "_read", return_value=raw):
                self.assertIsNone(status._cpu_limit())

    def test_memory_missing_and_unlimited_have_no_ratio(self):
        for raw in ("max", "-1", str(2**63 - 1), None):
            files = {"/proc/self/cgroup": "0::/", "/sys/fs/cgroup/memory.current": "10", "/sys/fs/cgroup/memory.max": raw}
            with self.subTest(raw=raw), mock.patch.object(status, "_read", side_effect=lambda p: files.get(p)):
                data = status._memory_stats()
                self.assertIsNone(data["limit_bytes"])
                self.assertIsNone(data["percent"])

    def test_module_age_not_uptime_and_independent_disk_fallbacks(self):
        usage = type("DU", (), {"total": 100, "used": 40, "free": 60})()
        with mock.patch.object(status, "_MODULE_LOADED_AT", 20), mock.patch.object(status.time, "monotonic", return_value=23.5), mock.patch.object(status, "_probe", return_value={"installed": False, "version": None}), mock.patch.object(status.shutil, "disk_usage", return_value=usage), mock.patch.object(status.os, "statvfs", side_effect=OSError):
            data = status._collect()
        self.assertEqual(data["module_age_seconds"], 3.5)
        self.assertNotIn("process_uptime_seconds", data)
        self.assertEqual(data["resources"]["mounted_root_disk"]["total_bytes"], 100)
        statvfs = type("ST", (), {"f_files": 20, "f_favail": 5})()
        with mock.patch.object(status, "_probe", return_value={"installed": False, "version": None}), mock.patch.object(status.shutil, "disk_usage", side_effect=OSError), mock.patch.object(status.os, "statvfs", return_value=statvfs):
            self.assertEqual(status._collect()["resources"]["mounted_root_disk"], {"inode_total": 20, "inode_available": 5})

    def test_missing_memory_details_are_omitted_from_html(self):
        data = fixture()
        data["resources"]["memory"] = {}
        body = status.render_page(data)
        self.assertNotIn("cgroup 当前用量", body)
        self.assertNotIn("cgroup 内存峰值", body)
        self.assertNotIn("cgroup 限额余量", body)
        self.assertIn("cgroup 内存限额", body)

    def test_routes_do_not_even_read_request_headers_or_body(self):
        class PrivateRequest:
            method = "GET"
            path = "/"
            @property
            def headers(self):
                raise AssertionError("request headers read")
            @property
            def bodyText(self):
                raise AssertionError("request body read")
        context = Context()
        context.req = PrivateRequest()
        with mock.patch.object(handler, "get_status", return_value=fixture()):
            self.assertEqual(handler.main(context)[1], 200)
            context.req.path = "/api/status"
            self.assertEqual(handler.main(context)[1], 200)


class NetworkIntegrationTests(NoExternalNetworkMixin, unittest.TestCase):
    def test_local_only_six_cards_supported_values_and_security_range(self):
        body = status.render_page(fixture())
        self.assertEqual(body.count('<article class="card">'), 6)
        for text in ("网络与 IP", "192.0.2.10/24", "2001:db8::10", "MTU 1500", "1.0 KiB / 2.0 KiB", "默认网关", "local_only", "不代表公网地址或入站可达", "可能临时或共享"):
            self.assertIn(text, body)
        for forbidden in ("ipify", "egress_ip", "出口观测", "出口查询"):
            self.assertNotIn(forbidden, body)
        self.assertNotIn("None", body); self.assertNotIn("<script", body)

    def test_missing_fields_and_network_values_are_html_escaped(self):
        data = fixture(); data["network"] = {"interfaces": [{"name": "<img src=x>", "ipv4": "192.0.2.4"}], "scope": "<img src=x>"}
        body = status.render_page(data)
        self.assertNotIn("<img src=x>", body); self.assertIn("&lt;img", body)
        self.assertEqual(body.count('<article class="card">'), 6)
        data["network"] = {"interfaces": [], "local_status": "unavailable", "external_queries": False}
        body = status.render_page(data)
        self.assertIn("本地接口枚举", body)
        self.assertIn("不可用", body)

    def test_never_create_tcp_socket_or_use_urllib_during_local_collection(self):
        from src import network
        original = network.socket.socket
        def guarded(family, kind, *args, **kwargs):
            if kind == socket.SOCK_STREAM:
                raise AssertionError("TCP connection prohibited")
            return original(family, kind, *args, **kwargs)
        with mock.patch.object(network.socket, "socket", side_effect=guarded), mock.patch("urllib.request.urlopen", side_effect=AssertionError("urllib prohibited")):
            network.collect_network()

    def test_non_status_routes_never_collect_network(self):
        with mock.patch.object(handler, "get_status", side_effect=AssertionError("unnecessary status collection")), \
             mock.patch.object(status, "collect_network", side_effect=AssertionError("unnecessary local network collection")):
            for method, path, code in (("GET", "/healthz", 200), ("GET", "/missing", 404), ("POST", "/api/status", 405)):
                with self.subTest(method=method, path=path):
                    self.assertEqual(handler.main(Context(method, path))[1], code)


if __name__ == "__main__":
    unittest.main()
