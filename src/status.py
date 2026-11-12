"""Bounded, read-only status collection for the current function process."""
from __future__ import annotations

import html
import math
import os
import platform
import re
import resource
import shutil
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from .network import collect_network

_CACHE_SECONDS = 30
_MODULE_LOADED_AT = time.monotonic()
_cache_lock = threading.Lock()
_cache_at = 0.0
_cache_value = None
_FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_CLI = {"curl": ("--version", r"^curl\s+([\w.+-]+)"), "wget": ("--version", r"^GNU Wget\s+([\w.+-]+)"), "git": ("--version", r"^git version\s+([\w.+-]+)")}
_PROC_FIELDS = {"VmRSS", "VmHWM", "VmSize", "Threads"}


def format_bytes(value):
    try:
        value = float(value)
        if not math.isfinite(value) or value < 0:
            return "不可用"
    except (TypeError, ValueError, OverflowError):
        return "不可用"
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


def format_duration(seconds):
    try:
        value = float(seconds)
        if not math.isfinite(value) or value < 0:
            return "不可用"
    except (TypeError, ValueError, OverflowError):
        return "不可用"
    if value < 1:
        return f"{value * 1000:.1f} 毫秒"
    if value < 60:
        return f"{value:.2f} 秒" if value < 10 else f"{value:.1f} 秒"
    if value < 3600:
        return f"{value / 60:.1f} 分钟"
    if value < 86400:
        return f"{value / 3600:.1f} 小时"
    return f"{value / 86400:.1f} 天"


def _read(path):
    try:
        with open(path, "r", encoding="ascii", errors="ignore") as f:
            return f.read(4096).strip()
    except (OSError, ValueError):
        return None


def _number(path):
    value = _read(path)
    if not value or value == "max":
        return None
    try:
        n = int(value)
        return n if n >= 0 else None
    except (ValueError, OverflowError):
        return None


def _cgroup_scope():
    """Return a trusted hierarchy kind only when this process is at its root."""
    text = _read("/proc/self/cgroup")
    if not text:
        return None
    entries = {}
    for line in text.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        controllers = fields[1].split(",") if fields[1] else []
        # Do not expose or otherwise use the member path beyond exact-root check.
        if fields[2] != "/":
            continue
        if fields[0] == "0" and not controllers:
            entries["v2"] = True
        for controller in controllers:
            entries[controller] = True
    if entries.get("v2"):
        return "v2"
    if entries.get("memory") and entries.get("cpu") and entries.get("cpuacct"):
        return "v1"
    return None


def _memory_stats():
    scope = _cgroup_scope()
    if scope == "v2":
        paths = ("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory.max")
        current, peak, raw_limit = map(_number, paths)
        maximum = raw_limit if raw_limit is not None and 0 < raw_limit < 2**60 else None
    elif scope == "v1":
        paths = ("/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.max_usage_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes")
        current, peak, raw_limit = map(_number, paths)
        maximum = raw_limit if raw_limit is not None and 0 < raw_limit < 2**60 else None
    else:
        current = peak = maximum = None
    if current is not None and current >= 2**60:
        current = None
    if peak is not None and peak >= 2**60:
        peak = None
    valid = current is not None and maximum is not None and current <= maximum
    return {"current_bytes": current, "peak_bytes": peak, "limit_bytes": maximum,
            "percent": round(current * 100 / maximum, 1) if valid else None,
            "remaining_bytes": maximum - current if valid else None}


def _memory_limit():
    return _memory_stats()["limit_bytes"]


def _cpu_limit():
    scope = _cgroup_scope()
    if scope == "v2":
        quota = _read("/sys/fs/cgroup/cpu.max")
        if not quota:
            return None
        fields = quota.split()
        try:
            if len(fields) != 2 or fields[0] == "max":
                return None
            q, p = int(fields[0]), int(fields[1])
            return round(q / p, 2) if q > 0 and p > 0 else None
        except (ValueError, ZeroDivisionError):
            return None
    if scope == "v1":
        q = next((v for path in ("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us") if (v := _number(path)) is not None), None)
        p = next((v for path in ("/sys/fs/cgroup/cpu/cpu.cfs_period_us", "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us") if (v := _number(path)) is not None), None)
        return round(q / p, 2) if q is not None and p is not None and q > 0 and p > 0 else None
    return None


def _swap_stats():
    if _cgroup_scope() != "v2":
        return None
    usage = _number("/sys/fs/cgroup/memory.swap.current")
    raw_limit = _number("/sys/fs/cgroup/memory.swap.max")
    limit = raw_limit if raw_limit is not None and raw_limit < 2**60 else None
    if usage is None or usage >= 2**60 or limit is None or usage > limit:
        return None
    return {"usage_bytes": usage, "limit_bytes": limit,
            "percent": round(usage * 100 / limit, 1) if limit > 0 else None}


def _cpu_stats():
    scope = _cgroup_scope()
    if scope == "v2":
        raw = _read("/sys/fs/cgroup/cpu.stat") or ""
        result = {}
        names = {"usage_usec": "usage_seconds", "user_usec": "user_seconds", "system_usec": "system_seconds",
                 "nr_periods": "periods", "nr_throttled": "throttled_periods", "throttled_usec": "throttled_seconds"}
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] not in names:
                continue
            try:
                value = int(fields[1])
                if value >= 0:
                    key = names[fields[0]]
                    result[key] = value / 1_000_000 if fields[0].endswith("_usec") else value
            except ValueError:
                pass
        return result or None
    if scope == "v1":
        result = {}
        usage = next((v for path in ("/sys/fs/cgroup/cpuacct/cpuacct.usage", "/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage") if (v := _number(path)) is not None), None)
        if usage is not None:
            result["usage_seconds"] = usage / 1_000_000_000
        raw = (_read("/sys/fs/cgroup/cpu/cpu.stat") or _read("/sys/fs/cgroup/cpu,cpuacct/cpu.stat") or "")
        for line in raw.splitlines():
            fields = line.split()
            if len(fields) != 2 or fields[0] not in {"nr_periods", "nr_throttled"}:
                continue
            try:
                value = int(fields[1])
                if value >= 0:
                    result["periods" if fields[0] == "nr_periods" else "throttled_periods"] = value
            except ValueError:
                pass
        return result or None
    return None


def _process_stats():
    result = {}
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        result["cpu_user_seconds"] = max(0.0, usage.ru_utime)
        result["cpu_system_seconds"] = max(0.0, usage.ru_stime)
        if platform.system() == "Linux" and usage.ru_maxrss >= 0:
            result["max_rss_bytes"] = int(usage.ru_maxrss * 1024)
    except (OSError, ValueError, AttributeError):
        pass
    fields = {}
    try:
        with open("/proc/self/status", encoding="ascii", errors="ignore") as status_file:
            for line in status_file:
                match = re.fullmatch(r"(VmRSS|VmHWM|VmSize|Threads):\s*(\d+)\s*(kB)?\s*", line)
                if match and match[1] in _PROC_FIELDS:
                    fields[match[1]] = int(match[2]) * 1024 if match[3] else int(match[2])
    except OSError:
        pass
    if fields:
        result["proc_status_bytes_or_count"] = fields
    return result or None


def _probe(name, args, pattern):
    executable = shutil.which(name, path=_FIXED_PATH)
    if not executable:
        return {"installed": False, "version": None}
    try:
        proc = subprocess.run([executable, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=0.55, check=False, shell=False, cwd="/",
            env={"PATH": _FIXED_PATH, "LANG": "C", "LC_ALL": "C"})
        match = re.search(pattern, proc.stdout[:4096].decode("utf-8", "replace"), re.MULTILINE)
        return {"installed": True, "version": match.group(1)[:60] if match else "版本不可识别"}
    except (OSError, subprocess.TimeoutExpired):
        return {"installed": True, "version": "探测超时或不可用"}


def _collect():
    started = time.monotonic()
    cli = {name: {"installed": False, "version": None} for name in _CLI}
    pool = ThreadPoolExecutor(max_workers=len(_CLI), thread_name_prefix="fixed-probe")
    futures = {pool.submit(_probe, name, *spec): name for name, spec in _CLI.items()}
    try:
        for future in as_completed(futures, timeout=0.8):
            try:
                cli[futures[future]] = future.result()
            except Exception:
                pass
    except TimeoutError:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    disk = None
    try:
        usage = shutil.disk_usage("/")
        disk = {"total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free,
                "available_bytes": usage.free, "total": format_bytes(usage.total), "used": format_bytes(usage.used),
                "free": format_bytes(usage.free), "available": format_bytes(usage.free),
                "usage_percent": round(usage.used * 100 / usage.total, 1) if usage.total > 0 else None}
    except (OSError, AttributeError):
        pass
    if disk is None:
        disk = {}
    try:
        stat = os.statvfs("/")
        disk["inode_total"] = stat.f_files
        if stat.f_favail >= 0:
            disk["inode_available"] = stat.f_favail
    except (OSError, AttributeError):
        pass
    memory = _memory_stats()
    try:
        import ssl
        ssl_version = ssl.OPENSSL_VERSION
    except Exception:
        ssl_version = None
    scope = "仅当前函数模块、Python 进程、通过成员根目录验证的 cgroup、根挂载与当前网络命名空间；挂载和网络可能共享，地址可能临时变化。不是主机、套餐或账户配额。"
    cpu_limit, swap, cpu_stat, process = _cpu_limit(), _swap_stats(), _cpu_stats(), _process_stats()
    network = collect_network()
    return {"snapshot_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "collection_seconds": round(max(0, time.monotonic() - started), 4),
            "scope": scope, "module_age_seconds": round(max(0, time.monotonic() - _MODULE_LOADED_AT), 3),
            "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                        "python_bits": struct.calcsize("P") * 8, "byteorder": sys.byteorder, "os": platform.system(),
                        "architecture": platform.machine(), "openssl": ssl_version},
            "resources": {"cpu_limit_cores": cpu_limit, "memory_limit_bytes": memory["limit_bytes"],
                          "memory_limit": format_bytes(memory["limit_bytes"]), "memory": memory,
                          "swap": swap, "cgroup_cpu_stat": cpu_stat, "process": process,
                          "mounted_root_disk": disk or None}, "tools": cli, "cache_seconds": _CACHE_SECONDS,
            "network": network,
            "note": "快照由请求触发；无轮询、扫描或保活。CPU/cgroup 和网络计数为累计值，不是实时速率；缓存命中时不重新采集。网络字段仅反映当前本地网络命名空间，不进行外部查询。"}


def get_status():
    global _cache_at, _cache_value
    now = time.monotonic()
    with _cache_lock:
        if _cache_value is not None and now - _cache_at < _CACHE_SECONDS:
            return dict(_cache_value)
        value = _collect()
        _cache_value, _cache_at = value, time.monotonic()
        return dict(value)


def render_page(status):
    esc = lambda value: html.escape(str(value))
    runtime = status.get("runtime") or {}
    resources = status.get("resources") or {}
    memory = resources.get("memory") or {}
    process = resources.get("process") or {}
    proc = process.get("proc_status_bytes_or_count") or {}
    disk = resources.get("mounted_root_disk") or {}
    cpu = resources.get("cgroup_cpu_stat") or {}
    network = status.get("network") or {}

    def rows(items):
        return "".join(f'<div class="row"><dt>{esc(label)}</dt><dd>{esc(value)}</dd></div>' for label, value in items if value is not None)

    optional_bytes = lambda value: format_bytes(value) if value is not None else None
    mem_rows = [("cgroup 内存限额", format_bytes(memory.get("limit_bytes"))),
                ("cgroup 当前用量", optional_bytes(memory.get("current_bytes"))),
                ("cgroup 内存峰值", optional_bytes(memory.get("peak_bytes"))),
                ("cgroup 限额占比", f'{memory["percent"]}%' if memory.get("percent") is not None else None),
                ("cgroup 限额余量", optional_bytes(memory.get("remaining_bytes")))]
    swap = resources.get("swap")
    if swap:
        mem_rows.extend((("Swap 用量", format_bytes(swap.get("usage_bytes"))), ("Swap 限额", format_bytes(swap.get("limit_bytes"))),
                         ("Swap 占比", f'{swap["percent"]}%' if swap.get("percent") is not None else None)))
    for field, title in (("VmRSS", "VmRSS 常驻内存"), ("VmHWM", "VmHWM 常驻峰值"), ("VmSize", "VmSize 虚拟地址空间（非物理内存）"), ("Threads", "进程线程数")):
        if field in proc:
            mem_rows.append((title, format_bytes(proc[field]) if field != "Threads" else str(proc[field])))
    if process.get("max_rss_bytes") is not None:
        mem_rows.append(("进程 maxRSS 峰值", format_bytes(process["max_rss_bytes"])))
    disk_rows = [("根挂载总容量（二进制）", disk.get("total")), ("已用", disk.get("used")),
                 ("可用空间", disk.get("available")), ("容量使用率", f'{disk["usage_percent"]}%' if disk.get("usage_percent") is not None else None),
                 ("inode 总数", disk.get("inode_total")), ("inode 可用数（f_favail）", disk.get("inode_available"))]
    cpu_rows = [("cgroup CPU 限额", f'{resources["cpu_limit_cores"]} 核' if resources.get("cpu_limit_cores") is not None else None)]
    for key, label in (("usage_seconds", "cgroup 累计 CPU 用量"), ("user_seconds", "用户态累计 CPU"), ("system_seconds", "内核态累计 CPU"),
                       ("periods", "周期数"), ("throttled_periods", "节流周期数"), ("throttled_seconds", "节流累计时间")):
        if key in cpu:
            cpu_rows.append((label, format_duration(cpu[key]) if "seconds" in key else cpu[key]))
    for key, label in (("cpu_user_seconds", "当前进程用户 CPU 累计"), ("cpu_system_seconds", "当前进程内核 CPU 累计")):
        if process.get(key) is not None:
            cpu_rows.append((label, format_duration(process[key])))
    runtime_rows = [("Python / 实现", f'{runtime.get("python", "")} / {runtime.get("implementation", "")}'),
                    ("系统 / 架构", f'{runtime.get("os", "")} / {runtime.get("architecture", "")}'),
                    ("位数 / 字节序", f'{runtime.get("python_bits", "")} / {runtime.get("byteorder", "")}'), ("OpenSSL", runtime.get("openssl"))]
    module_rows = [("模块载入时长（非 uptime）", format_duration(status.get("module_age_seconds")) if status.get("module_age_seconds") is not None else None),
                   ("快照 UTC", status.get("snapshot_utc")),
                   ("本次采集耗时", format_duration(status.get("collection_seconds")) if status.get("collection_seconds") is not None else None),
                   ("暖进程缓存", f'{status["cache_seconds"]} 秒' if status.get("cache_seconds") is not None else None)]
    tools = "".join(f'<div class="row"><dt>{esc(name)}</dt><dd>{esc(info.get("version") or ("已安装" if info.get("installed") else "未安装"))}</dd></div>' for name, info in (status.get("tools") or {}).items())
    network_rows = [("本地接口枚举", {"available": "可用", "unavailable": "不可用"}.get(network.get("local_status")))]
    for interface in (network.get("interfaces") or [])[:16]:
        name = interface.get("name", "接口")
        if interface.get("ipv4"):
            suffix = f'/{interface["ipv4_prefix_length"]}' if interface.get("ipv4_prefix_length") is not None else ""
            network_rows.append((f"{name} IPv4", interface["ipv4"] + suffix))
        if interface.get("ipv6"):
            network_rows.append((f"{name} IPv6", "、".join(interface["ipv6"][:8])))
        link = []
        if interface.get("mtu") is not None:
            link.append(f'MTU {interface["mtu"]}')
        if interface.get("admin_up") is not None:
            link.append("UP" if interface["admin_up"] else "DOWN")
        if interface.get("running"):
            link.append("RUNNING")
        if link:
            network_rows.append((f"{name} 接口标记", " · ".join(link)))
        counters = interface.get("counters") or {}
        if counters.get("rx_bytes") is not None and counters.get("tx_bytes") is not None:
            network_rows.append((f"{name} 累计收 / 发", f'{format_bytes(counters["rx_bytes"])} / {format_bytes(counters["tx_bytes"])}'))
        if all(counters.get(k) is not None for k in ("rx_packets", "rx_errors", "rx_dropped", "tx_packets", "tx_errors", "tx_dropped")):
            counts = lambda direction: "/".join(f'{counters[direction + "_" + k]:,}' for k in ("packets", "errors", "dropped"))
            network_rows.append((f"{name} 包/错/丢（收；发）", f'{counts("rx")}；{counts("tx")}'))
    gateway = network.get("default_ipv4_gateway") or {}
    if gateway.get("ipv4"):
        network_rows.append((f'默认网关 · {gateway.get("interface", "IPv4")}', gateway["ipv4"]))
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Appwrite Functions · 状态</title><style>
:root{{--bg:#0b0d17;--panel:#111b2a;--line:#2a3543;--text:#edf2f8;--muted:#a7b4c5;--accent:#a8caff}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}}main{{width:min(1060px,calc(100% - 40px));margin:0 auto;padding:52px 0 36px}}header{{margin-bottom:32px}}.eyebrow{{color:var(--muted);font-size:.78rem;letter-spacing:.12em}}h1{{margin:8px 0 12px;font-size:clamp(2rem,4vw,2.75rem);line-height:1.2;letter-spacing:-.03em}}header p{{margin:0 0 14px;color:var(--muted)}}.source{{color:var(--muted);overflow-wrap:anywhere}}a{{color:var(--accent);text-underline-offset:3px}}a:hover{{color:#d2e3ff}}a:focus-visible{{outline:2px solid var(--accent);outline-offset:4px;border-radius:2px}}.grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px}}.card{{min-width:0;border:1px solid var(--line);border-radius:14px;background:var(--panel);padding:18px;box-shadow:0 0 0 1px #ffffff03 inset}}.card h2{{margin:0 0 18px;color:var(--accent);font-size:1.12rem;line-height:1.35}}dl{{margin:0;padding:0}}.row{{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid #ffffff12}}.row:last-child{{padding-bottom:0;border-bottom:0}}.row:first-child{{padding-top:0}}dt{{color:var(--muted);min-width:0}}dd{{margin:0;text-align:right;font-weight:650;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}}.notice{{margin:24px 0 0;padding:18px 20px;border:1px solid var(--line);border-radius:14px;color:var(--muted);line-height:1.7}}footer{{margin-top:22px;color:var(--muted);font-size:.875rem;line-height:1.8}}@media(max-width:820px){{.grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}}}@media(max-width:560px){{main{{width:calc(100% - 32px);padding-top:30px}}header{{margin-bottom:24px}}.grid{{grid-template-columns:minmax(0,1fr);gap:14px}}.card{{padding:18px}}.card h2{{margin-bottom:16px}}.notice{{padding:16px}}}}
.card h3{{margin:20px 0 12px;color:var(--accent);font-size:.95rem}}.hint{{margin:16px 0 0;color:var(--muted);font-size:.8rem;line-height:1.7}}
</style></head><body><main><header><div class="eyebrow">APPWRITE CLOUD · FUNCTIONS</div><h1>函数运行状态</h1><p>按需执行环境的只读快照</p><div class="source">公开源码仓库：<a href="https://github.com/mathowvan/appwrite-status">github.com/mathowvan/appwrite-status</a></div></header><section class="grid" aria-label="运行环境状态">
<article class="card"><h2>内存与进程</h2><dl>{rows(mem_rows)}</dl></article><article class="card"><h2>根挂载磁盘</h2><dl>{rows(disk_rows)}</dl></article><article class="card"><h2>CPU</h2><dl>{rows(cpu_rows)}</dl></article><article class="card"><h2>运行时与工具</h2><dl>{rows(runtime_rows)}</dl><h3>固定工具探测</h3><dl>{tools}</dl></article><article class="card"><h2>网络与 IP</h2><dl>{rows(network_rows)}</dl><p class="hint">local_only：仅当前网络命名空间的 Linux 只读 ioctl 与 /proc/net 数据，无任何外部查询。地址可能临时或共享，不代表公网地址或入站可达。接口流量是累计值，不是速率或项目月带宽。</p></article><article class="card"><h2>模块与快照</h2><dl>{rows(module_rows)}</dl></article></section><section class="notice">范围：{esc(status.get("scope", ""))}<br>CPU/cgroup 与网络计数为累计值；缓存命中不重新采集。成员路径无法验证时省略 cgroup 详细读数；手动刷新获取新快照，本页不轮询、不保活。</section><footer>资源数值不代表主机、套餐或账户配额。网络信息仅来自当前本地网络命名空间；本应用不查询公网出口地址。<br><a href="/api/status">JSON 状态 API</a> · <a href="/healthz">健康检查</a></footer></main></body></html>'''
