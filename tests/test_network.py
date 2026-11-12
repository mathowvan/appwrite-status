import json
import socket
import unittest
from unittest import mock

from src import network


class NetworkTests(unittest.TestCase):
    def test_no_external_network_code_or_urllib_import(self):
        import pathlib
        source = pathlib.Path(network.__file__).read_text(encoding="utf-8")
        for forbidden in ("urllib", "ipify", "egress_ip", "egress_provider", "_cached_egress", "_probe_egress", "threading"):
            self.assertNotIn(forbidden, source)
        self.assertFalse(hasattr(network, "urllib"))
        self.assertFalse(hasattr(network, "_probe_egress"))
        self.assertFalse(hasattr(network, "_cached_egress"))

    def test_only_udp_ioctl_socket_is_created_never_tcp(self):
        fake_sock = mock.Mock()
        fake_sock.fileno.return_value = 12
        with mock.patch.object(network.socket, "if_nameindex", return_value=[(1, "eth0")]), \
             mock.patch.object(network.socket, "socket", return_value=fake_sock) as factory, \
             mock.patch.object(network.fcntl, "ioctl", side_effect=OSError()), \
             mock.patch.object(network, "_read_fixed", return_value=None):
            interfaces, status = network._interfaces()
        self.assertEqual((len(interfaces), status), (1, "available"))
        self.assertEqual(factory.call_args_list, [mock.call(socket.AF_INET, socket.SOCK_DGRAM)])
        fake_sock.connect.assert_not_called()
        fake_sock.send.assert_not_called()

    def test_collect_local_schema_and_no_unapproved_file_reads(self):
        with mock.patch.object(network.socket, "if_nameindex", return_value=[(1, "lo")]), \
             mock.patch.object(network, "_interface_ioctl", return_value={}), \
             mock.patch.object(network, "_read_fixed", return_value=None) as read:
            result = network.collect_network()
        self.assertEqual({c.args[0] for c in read.call_args_list}, {"/proc/net/if_inet6", "/proc/net/dev", "/proc/net/route"})
        self.assertEqual(result["scope"], "local_only: current network namespace; not public egress or inbound reachability")
        self.assertFalse(result["external_queries"])
        self.assertIn("no external queries", result["note"])
        self.assertFalse(set(result) & {"egress_ip", "egress_status", "egress_provider", "egress_probe_policy"})
        json.dumps(result)

    def test_local_parsers_counters_and_gateway_flags(self):
        contents = {
            "/proc/net/dev": b"head\nhead\n eth0: 10 2 1 0 0 0 0 0 20 3 4 0 0 0 0 0\n" + b"bad: " + b"x " * 20,
            "/proc/net/route": b"Iface Destination Gateway Flags RefCnt Use Metric Mask\neth0 00000000 0101A8C0 0003 0 0 0 00000000\neth0 00000000 0101A8C0 0002 0 0 0 00000000\n",
        }
        with mock.patch.object(network, "_read_fixed", side_effect=lambda p, limit=network._MAX_FILE: contents.get(p)):
            counters, gateway = network._netdev(), network._gateway()
        self.assertEqual((counters["eth0"]["rx_bytes"], counters["eth0"]["tx_bytes"]), (10, 20))
        self.assertIn("cumulative", counters["eth0"]["counter_scope"])
        self.assertEqual((gateway["ipv4"], gateway["interface"]), ("192.168.1.1", "eth0"))

    def test_interface_cap_validation_ipv6_and_ioctl_data(self):
        raw6 = b"20010db8000000000000000000000001 02 00 00 00000000 eth0\n" * 20
        with mock.patch.object(network.socket, "if_nameindex", return_value=[(i, f"eth{i}") for i in range(20)] + [(99, "bad name")]), \
             mock.patch.object(network, "_interface_ioctl", return_value={"mtu": 1500}) as ioctl, \
             mock.patch.object(network, "_read_fixed", return_value=raw6):
            result, state = network._interfaces()
        self.assertEqual((len(result), state), (16, "available"))
        self.assertEqual(result[0]["ipv6"], ["2001:db8::1"] if result[0]["name"] == "eth0" else [])
        self.assertEqual(ioctl.call_count, 16)
        self.assertNotIn("bad name", [entry["name"] for entry in result])

    def test_ioctl_reports_ipv4_prefix_mtu_flags_and_closes_socket(self):
        fake_sock = mock.Mock(); fake_sock.fileno.return_value = 12
        def ioctl(fd, code, request):
            self.assertEqual(fd, 12)
            value = bytearray(256)
            if code in (0x8915, 0x891B):
                value[20:24] = socket.inet_aton("192.0.2.12" if code == 0x8915 else "255.255.255.0")
            elif code == 0x8921: network.struct.pack_into("i", value, 16, 1500)
            elif code == 0x8913: network.struct.pack_into("H", value, 16, 0x41)
            return bytes(value)
        with mock.patch.object(network.socket, "socket", return_value=fake_sock), mock.patch.object(network.fcntl, "ioctl", side_effect=ioctl):
            result = network._interface_ioctl("eth0")
        self.assertEqual((result["ipv4"], result["ipv4_prefix_length"], result["mtu"]), ("192.0.2.12", 24, 1500))
        self.assertTrue(result["admin_up"] and result["running"])
        fake_sock.close.assert_called_once()
        fake_sock.connect.assert_not_called()

    def test_read_failure_degrades_without_leaking_errors(self):
        with mock.patch.object(network.socket, "if_nameindex", side_effect=OSError("secret")), \
             mock.patch.object(network, "_netdev", side_effect=OSError("private")), \
             mock.patch.object(network, "_gateway", side_effect=OSError("hidden")):
            result = network.collect_network()
        self.assertEqual((result["interfaces"], result["local_status"]), ([], "unavailable"))
        self.assertNotIn("secret", str(result)); self.assertNotIn("private", str(result)); self.assertNotIn("hidden", str(result))

    def test_file_reader_is_bounded(self):
        handle = mock.mock_open(); handle.return_value.read.return_value = b"x" * (network._MAX_FILE + 1)
        with mock.patch("builtins.open", handle):
            self.assertIsNone(network._read_fixed("/proc/net/dev"))
        handle.return_value.read.assert_called_once_with(network._MAX_FILE + 1)

    def test_invalid_interface_names_and_ipv6_duplicates_are_rejected(self):
        raw6 = (b"20010db8000000000000000000000001 02 00 00 00000000 eth0\n" * 2
                + b"nothex 02 00 00 00000000 eth0\n"
                + b"20010db8000000000000000000000002 03 00 00 00000000 other\n")
        with mock.patch.object(network.socket, "if_nameindex", return_value=[(1, "bad name"), (2, "eth0;curl"), (3, "x" * 16), (4, "eth0")]), \
             mock.patch.object(network, "_interface_ioctl", return_value={}) as ioctl, \
             mock.patch.object(network, "_read_fixed", return_value=raw6):
            interfaces, state = network._interfaces()
        self.assertEqual(state, "available")
        self.assertEqual([entry["name"] for entry in interfaces], ["eth0"])
        self.assertEqual(interfaces[0]["ipv6"], ["2001:db8::1"])
        ioctl.assert_called_once_with("eth0")

    def test_gateway_requires_default_up_gateway_route(self):
        for row in ("eth0 00000001 0101A8C0 0003 0 0 0 00000000", "eth0 00000000 0101A8C0 0002 0 0 0 00000000",
                    "eth0 00000000 0101A8C0 0001 0 0 0 00000000", "eth0 00000000 00000000 0003 0 0 0 00000000",
                    "eth0 00000000 0101A8C0 0003 0 0 0 FFFFFFFF", "eth0 00000000 GARBAGE 0003 0 0 0 00000000"):
            with self.subTest(row=row), mock.patch.object(network, "_read_fixed", return_value=("header\n" + row + "\n").encode()):
                self.assertIsNone(network._gateway())

    def test_negative_or_malformed_interface_counters_are_omitted(self):
        raw = b"header\nheader\n"
        raw += b"eth0: " + b"0 " * 16 + b"\nnegative: -1 " + b"0 " * 15 + b"\n"
        raw += b"invalid: x " + b"0 " * 15 + b"\nshort: 1 2 3\n"
        with mock.patch.object(network, "_read_fixed", return_value=raw):
            self.assertEqual(set(network._netdev()), {"eth0"})
        with mock.patch.object(network, "_read_fixed", return_value=None):
            self.assertEqual(network._netdev(), {})

    def test_socket_calls_are_local_enumeration_and_ioctl_only(self):
        import ast
        import pathlib
        tree = ast.parse(pathlib.Path(network.__file__).read_text())
        calls = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "socket":
                    calls.add(node.func.attr)
                if node.func.value.id == "sock":
                    self.assertIn(node.func.attr, {"fileno", "close"})
        self.assertEqual(calls, {"socket", "if_nameindex"})
        self.assertFalse(hasattr(network, "_URL"))


if __name__ == "__main__":
    unittest.main()
