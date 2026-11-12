"""Read-only, bounded status collection for ephemeral Appwrite function instances."""
from __future__ import annotations

import html
import json
import os
import platform
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

_CACHE_SECONDS = 30
_MODULE_LOADED_AT = time.monotonic()
_cache_lock = threading.Lock()
_cache_at = 0.0
_cache_value = None
_FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Fixed executable names and fixed version arguments only. No user-supplied input.
_CLI = {"curl": ("--version", r"^curl\s+([\w.+-]+)"), "wget": ("--version", r"^GNU Wget\s+([\w.+-]+)"), "git": ("--version", r"^git version\s+([\w.+-]+)")}

def format_bytes(value):
    if value is None or value < 0:
        return "不可用"
    value = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024

def format_duration(seconds):
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days: parts.append(f"{days}天")
    if hours or days: parts.append(f"{hours}小时")
    if minutes or hours or days: parts.append(f"{minutes}分钟")
    parts.append(f"{secs}秒")
    return " ".join(parts)

def _read(path):
    try:
        with open(path, "r", encoding="ascii", errors="ignore") as f:
            return f.read(4096).strip()
    except (OSError, ValueError):
        return None

def _number(path):
    value = _read(path)
    if not value or value == "max": return None
    try: return int(value)
    except ValueError: return None

def _memory_limit():
    # cgroup v2 then v1; only read fixed system files.
    for path in ("/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"):
        value = _number(path)
        if value is not None and value > 0 and value < 2**60:
            return value
    return None

def _cpu_limit():
    quota = _read("/sys/fs/cgroup/cpu.max")
    if quota:
        fields = quota.split()
        try:
            if len(fields) == 2:
                if fields[0] == "max":
                    return None
                q, p = int(fields[0]), int(fields[1])
                return round(q / p, 2) if q > 0 and p > 0 else None
        except (ValueError, ZeroDivisionError):
            return None
    q, p = _number("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"), _number("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    return round(q / p, 2) if q is not None and p is not None and q > 0 and p > 0 else None

def _probe(name, args, pattern):
    exe = shutil.which(name, path=_FIXED_PATH)
    if not exe: return {"installed": False, "version": None}
    try:
        proc = subprocess.run([exe, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=0.55, check=False, shell=False, cwd="/",
            env={"PATH": _FIXED_PATH, "LANG": "C", "LC_ALL": "C"})
        text = proc.stdout[:4096].decode("utf-8", "replace")
        match = re.search(pattern, text, re.MULTILINE)
        return {"installed": True, "version": match.group(1)[:60] if match else "版本不可识别"}
    except (OSError, subprocess.TimeoutExpired):
        return {"installed": True, "version": "探测超时或不可用"}

def _collect():
    # Concurrent fixed probes share a hard aggregate wait budget; late tasks never delay response.
    cli = {name: {"installed": False, "version": None} for name in _CLI}
    pool = ThreadPoolExecutor(max_workers=len(_CLI), thread_name_prefix="fixed-probe")
    futures = {pool.submit(_probe, name, *spec): name for name, spec in _CLI.items()}
    try:
        for future in as_completed(futures, timeout=0.8):
            try: cli[futures[future]] = future.result()
            except Exception: pass
    except TimeoutError:
        pass
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    try:
        disk = shutil.disk_usage("/")
        disk_data = {"total_bytes": disk.total, "free_bytes": disk.free, "total": format_bytes(disk.total), "free": format_bytes(disk.free)}
    except OSError:
        disk_data = None
    return {
        "scope": "单次函数执行所见的临时运行实例；不是账户配额、独占硬件、平台 uptime 或持续可用性保证。",
        "module_age_seconds": round(time.monotonic() - _MODULE_LOADED_AT, 3),
        "runtime": {"python": platform.python_version(), "os": platform.system(), "architecture": platform.machine()},
        "resources": {"cpu_limit_cores": _cpu_limit(), "memory_limit_bytes": _memory_limit(), "memory_limit": format_bytes(_memory_limit()), "mounted_root_disk": disk_data},
        "tools": cli,
        "note": "数据仅反映函数执行环境可见的有限读数；cgroup、挂载与实例隔离会影响结果。",
    }

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
    # All variable text is escaped before insertion; JSON API remains separate.
    py = html.escape(status["runtime"]["python"])
    os_name = html.escape(status["runtime"]["os"])
    arch = html.escape(status["runtime"]["architecture"])
    module_age = html.escape(format_duration(status["module_age_seconds"]))
    cpu = html.escape(str(status["resources"]["cpu_limit_cores"] if status["resources"]["cpu_limit_cores"] is not None else "不可用"))
    mem = html.escape(status["resources"]["memory_limit"])
    disk = status["resources"]["mounted_root_disk"]
    disk_text = html.escape(f"{disk['free']} 可用 / {disk['total']} 总量" if disk else "不可用")
    tools = "".join(f"<li><span>{html.escape(name)}</span><strong>{html.escape(info['version'] or ('已安装' if info['installed'] else '未安装'))}</strong></li>" for name, info in status["tools"].items())
    disclaimer = html.escape(status["scope"])
    return f'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>Appwrite Functions · 状态</title><style>
<style>:root{{--bg:#101014;--panel:#19191d;--line:#303037;--text:#f4f2f4;--muted:#aaa7ae;--pink:#fd366e}}*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,sans-serif}}main{{width:min(940px,100% - 32px);margin:auto;padding:40px 0}}.card,li,.notice{{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:16px;margin:12px 0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}.label{{color:var(--muted)}}.value{{font-size:1.3rem;font-weight:700}}a{{color:#ff89a9}}</style></head><body><main><header><div><div>APPWRITE CLOUD · FUNCTIONS</div><h1>函数运行状态</h1><p>按需执行环境的只读快照</p></div><a href="https://github.com/mathowvan/appwrite-status">GitHub 项目 ↗</a></header><section class="notice"><strong>临时实例范围</strong><br>{disclaimer}<br>手动刷新以获取新快照；本页面不轮询、不做保活。</section><section class="grid"><article class="card"><div class="label">函数模块载入时长</div><div class="value">{module_age}</div></article><article class="card"><div class="label">Python · 操作系统 · 架构</div><div class="value">{py}<br>{os_name} · {arch}</div></article><article class="card"><div class="label">可读 CPU 限额（核）</div><div class="value">{cpu}</div></article><article class="card"><div class="label">可读内存限制</div><div class="value">{mem}</div></article><article class="card"><div class="label">当前根挂载磁盘</div><div class="value">{disk_text}</div></article></section><h2>固定工具探测</h2><ul>{tools}</ul><footer>只展示本地安全读数。资源数值不代表 Appwrite 账户配额、独占硬件或函数可用性。<br><a href="/api/status">JSON 状态 API</a> · <a href="/healthz">健康检查</a></footer></main></body></html>'''
