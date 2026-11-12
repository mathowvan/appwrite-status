"""Bounded, read-only network facts for the current Linux network namespace."""
from __future__ import annotations

import fcntl
import ipaddress
import re
import socket
import struct
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

_MAX_INTERFACES = 16
_MAX_FILE = 32768
_PROBE_TIMEOUT = 1.2
_URL = "https://api.ipify.org"
_IFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_cache_lock = threading.Lock()
_probe_attempted = False
_cache_result = None


def _read_fixed(path, limit=_MAX_FILE):
    try:
        with open(path, "rb") as stream:
            data = stream.read(limit + 1)
        return data if len(data) <= limit else None
    except (OSError, ValueError):
        return None


def _interface_ioctl(name):
    result = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return result
    try:
        request = struct.pack("256s", name.encode("ascii"))
        for code, key in ((0x8915, "ipv4"), (0x891B, "netmask"), (0x8921, "mtu"), (0x8913, "flags")):
            try:
                response = fcntl.ioctl(sock.fileno(), code, request)
                if key in {"ipv4", "netmask"}:
                    result[key] = str(ipaddress.IPv4Address(response[20:24]))
                elif key == "mtu":
                    mtu = struct.unpack_from("i", response, 16)[0]
                    if mtu > 0:
                        result[key] = mtu
                else:
                    flags = struct.unpack_from("H", response, 16)[0]
                    result["admin_up"], result["running"] = bool(flags & 1), bool(flags & 0x40)
            except (OSError, ValueError, UnicodeError, struct.error):
                continue
    finally:
        sock.close()
    mask = result.pop("netmask", None)
    if result.get("ipv4") and mask is not None:
        try:
            result["ipv4_prefix_length"] = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
        except ValueError:
            pass
    if "ipv4" in result:
        result["ipv4_source"] = "Linux SIOCGIFADDR/SIOCGIFNETMASK"
    if "mtu" in result or "admin_up" in result:
        result["link_source"] = "Linux SIOCGIFMTU/SIOCGIFFLAGS"
    return result


def _interfaces():
    try:
        names = socket.if_nameindex()[:_MAX_INTERFACES]
    except (OSError, AttributeError):
        return [], "unavailable"
    result = []
    for _, raw_name in names:
        name = str(raw_name)
        if not _IFACE.fullmatch(name):
            continue
        item = {"name": name, "source": "current network namespace"}
        item.update(_interface_ioctl(name))
        result.append(item)
    raw6 = _read_fixed("/proc/net/if_inet6")
    if raw6 is not None:
        for line in raw6.decode("ascii", "ignore").splitlines()[:128]:
            fields = line.split()
            if len(fields) != 6 or not _IFACE.fullmatch(fields[5]) or not re.fullmatch(r"[0-9a-fA-F]{32}", fields[0]):
                continue
            target = next((entry for entry in result if entry["name"] == fields[5]), None)
            if target is None:
                continue
            try:
                address = str(ipaddress.IPv6Address(bytes.fromhex(fields[0])))
                addresses = target.setdefault("ipv6", [])
                if len(addresses) < 8 and address not in addresses:
                    addresses.append(address)
                    target["ipv6_source"] = "/proc/net/if_inet6"
            except ValueError:
                continue
    return result, "available"


def _netdev():
    raw = _read_fixed("/proc/net/dev")
    if raw is None:
        return {}
    counters = {}
    for line in raw.decode("ascii", "ignore").splitlines()[2:2 + _MAX_INTERFACES + 8]:
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        name = name.strip()
        fields = values.split()
        if not _IFACE.fullmatch(name) or len(fields) != 16:
            continue
        try:
            nums = [int(v, 10) for v in fields]
            if min(nums) < 0:
                continue
        except ValueError:
            continue
        counters[name] = {"rx_bytes": nums[0], "rx_packets": nums[1], "rx_errors": nums[2], "rx_dropped": nums[3],
                          "tx_bytes": nums[8], "tx_packets": nums[9], "tx_errors": nums[10], "tx_dropped": nums[11],
                          "source": "/proc/net/dev",
                          "counter_scope": "cumulative namespace/interface counters; not current rate or project monthly bandwidth"}
    return counters


def _gateway():
    raw = _read_fixed("/proc/net/route", 8192)
    if raw is None:
        return None
    for line in raw.decode("ascii", "ignore").splitlines()[1:34]:
        fields = line.split()
        if len(fields) < 8 or not _IFACE.fullmatch(fields[0]):
            continue
        try:
            destination, gateway, flags, mask = int(fields[1], 16), int(fields[2], 16), int(fields[3], 16), int(fields[7], 16)
            if destination != 0 or mask != 0 or flags & 3 != 3 or gateway == 0:
                continue
            address = str(ipaddress.IPv4Address(struct.pack("<I", gateway)))
            return {"ipv4": address, "interface": fields[0], "source": "default route in /proc/net/route"}
        except (ValueError, OSError, struct.error):
            continue
    return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe_egress(opener=None):
    """One fixed HTTPS request; no proxy, redirect, retry, or fallback.

    The socket timeout bounds connection/reads, not system DNS resolution time.
    """
    try:
        if opener is None:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        request = urllib.request.Request(_URL, headers={"Accept": "text/plain"}, method="GET")
        with opener.open(request, timeout=_PROBE_TIMEOUT) as response:
            if getattr(response, "status", 200) != 200:
                return None
            body = response.read(129)
        if len(body) > 128:
            return None
        text = body.decode("ascii").strip()
        parsed = ipaddress.ip_address(text)
        if not parsed.is_global or parsed.is_multicast or parsed.is_unspecified or parsed.is_reserved or str(parsed) != text:
            return None
        return {"ip": str(parsed), "family": parsed.version, "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "provider": "api.ipify.org", "source": "single fixed HTTPS egress probe", "shared_or_transient": True,
                "warning": "egress IP may be shared or transient"}
    except (OSError, ValueError, UnicodeError, urllib.error.URLError, TimeoutError):
        return None


def _cached_egress(opener=None):
    """Make at most one external probe in this warm process, including failures."""
    global _probe_attempted, _cache_result
    with _cache_lock:
        if _probe_attempted:
            return dict(_cache_result) if _cache_result is not None else None
        _probe_attempted = True
        try:
            _cache_result = _probe_egress(opener)
        except Exception:
            _cache_result = None
        return dict(_cache_result) if _cache_result is not None else None


def collect_network(*, opener=None):
    """Collect local namespace data and cached-on-request public egress IP info."""
    try:
        interfaces, local_status = _interfaces()
    except Exception:
        interfaces, local_status = [], "unavailable"
    try:
        counters = _netdev()
    except Exception:
        counters = {}
    for item in interfaces:
        if item["name"] in counters:
            item["counters"] = counters[item["name"]]
    try:
        gateway = _gateway()
    except Exception:
        gateway = None
    try:
        public_ip = _cached_egress(opener=opener)
    except Exception:
        public_ip = None
    result = {"collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "scope": "current network namespace; interfaces, addresses and egress may be shared or transient",
              "interfaces": interfaces, "local_status": local_status, "interfaces_limit": _MAX_INTERFACES,
              "egress_ip": public_ip, "egress_status": "available" if public_ip else "unavailable",
              "egress_provider": "api.ipify.org", "egress_probe_policy": "at most one attempt per warm process; failures are not retried",
              "note": "request-triggered only; no polling, scanning, retries or keepalive"}
    if gateway is not None:
        result["default_ipv4_gateway"] = gateway
    return result
