#!/usr/bin/env python3
"""healthD — painel local de saúde da máquina (journal, systemd, hardware, disco, frota)."""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import grp
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

APP_NAME = "healthD"
VERSION = "0.14.0"
WEB_ROOT = Path(__file__).resolve().parent / "web"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9999
DEFAULT_LINES = 80_000
CACHE_TTL_SEC = 12
TIPS_TTL_SEC = 45 * 60
CHAT_TTL_SEC = 2 * 3600
CHAT_MAX_FOLLOWUPS = 20
CHAT_MAX_MESSAGE = 4000
CONFIG_DIR = Path.home() / ".config" / "healthd"
LEGACY_CONFIG_DIR = Path.home() / ".config" / "journalctl-obs"
AUTH_GROUP = "healthd"
SESSION_TTL_SEC = 12 * 3600
SESSION_COOKIE = "healthd_session"
NOLOGIN_SHELLS = frozenset({"nologin", "false", "sync", "halt", "shutdown", ""})
REMOTE_MAX_BYTES = 8_000_000
REMOTE_HEALTH_TIMEOUT = 2.5
GROQ_MODELS = ("openai/gpt-oss-20b", "qwen/qwen3.6-27b", "qwen/qwen3.8-27b", "openai/gpt-oss-120b")
GEMINI_MODELS = (
    "gemini-flash-latest",
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
)
OPENROUTER_MODEL = "meta-llama/llama-3.3-70b-instruct:free"

PRIORITY_META = {
    0: {"id": "emerg", "label": "Emergência", "short": "emerg", "weight": 12.0, "rank": 0},
    1: {"id": "alert", "label": "Alerta", "short": "alert", "weight": 10.0, "rank": 1},
    2: {"id": "crit", "label": "Crítico", "short": "crit", "weight": 8.5, "rank": 2},
    3: {"id": "err", "label": "Erro", "short": "err", "weight": 5.5, "rank": 3},
    4: {"id": "warning", "label": "Aviso", "short": "warning", "weight": 2.2, "rank": 4},
    5: {"id": "notice", "label": "Notice", "short": "notice", "weight": 0.6, "rank": 5},
    6: {"id": "info", "label": "Info", "short": "info", "weight": 0.15, "rank": 6},
    7: {"id": "debug", "label": "Debug", "short": "debug", "weight": 0.05, "rank": 7},
}

SINCE_MAP = {
    "1h": ("1 hour ago", "última 1 hora"),
    "6h": ("6 hours ago", "últimas 6 horas"),
    "24h": ("1 day ago", "últimas 24 horas"),
    "7d": ("7 days ago", "últimos 7 dias"),
    "boot": (None, "desde o boot"),
}

IMPACT_KEYWORDS = (
    (re.compile(r"\b(oom|out of memory|killed process|memory cgroup)\b", re.I), 2.4, "memória"),
    (re.compile(r"\b(segfault|segmentation fault|core dumped|fatal signal)\b", re.I), 2.2, "crash"),
    (re.compile(r"\b(kernel panic|BUG:|oops:|hard lockup|watchdog)\b", re.I), 2.8, "kernel"),
    (re.compile(r"\b(i/?o error|read-only file system|ext4|xfs|nvme|disk|no space)\b", re.I), 2.5, "disco"),
    (re.compile(r"\b(timeout|timed out|deadline exceeded)\b", re.I), 1.6, "latência"),
    (re.compile(r"\b(failed|failure|fatal|emergency|error)\b", re.I), 1.45, "falha"),
    (re.compile(r"\b(connection refused|dns|network unreachable|link is down)\b", re.I), 1.7, "rede"),
    (re.compile(r"\b(apparmor|denied|permission denied|unauthorized)\b", re.I), 1.15, "acesso"),
)

CRITICAL_UNITS = {
    "kernel": 1.55,
    "systemd": 1.35,
    "systemd-networkd.service": 1.4,
    "NetworkManager.service": 1.35,
    "systemd-resolved.service": 1.25,
    "dbus.service": 1.3,
    "ssh.service": 1.2,
    "sshd.service": 1.2,
}

RE_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)
RE_HEX = re.compile(r"\b0x[0-9a-f]+\b", re.I)
RE_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
RE_MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
RE_PID = re.compile(r"\[\d+\]")
RE_NUM = re.compile(r"\b\d+\b")
RE_AUDIT_TYPE = re.compile(r"\btype=(\w+)", re.I)
RE_AUDIT_OP = re.compile(r'operation="([^"]+)"', re.I)
RE_AUDIT_PROFILE = re.compile(r'profile="([^"]+)"', re.I)
RE_FAILED_UNIT = re.compile(r"Failed to (?:start|stop|restart) ([^\s.]+\.service)", re.I)
RE_RESTART_JOB = re.compile(r"Scheduled restart job, restarting (.+?)\.", re.I)
RE_OOM_KILL = re.compile(r"Killed process (\d+) \(([^)]+)\)", re.I)
RE_OOM_TASK = re.compile(r"\boom-kill:.*?\btask=(\S+)", re.I)
RE_UNIT_SAFE = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,256}$")
RE_HOST_ID = re.compile(r"^[a-z0-9]{8,24}$")
RE_DNS_NAME = re.compile(
    r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*)$"
)
RE_REMOTE_API = re.compile(
    r"^/api/remote/([a-z0-9]{8,24})/"
    r"(health|report|ai(?:-chat)?|live|disk(?:/ls|/open)?|units|unit-logs|unit-tips|"
    r"unit-disable|machine(?:-tips)?|tips)$"
)

ESSENTIAL_UNIT_NAMES = frozenset(
    {
        "dbus.service",
        "dbus-broker.service",
        "dbus-daemon.service",
        "networkmanager.service",
        "networkmanager-wait-online.service",
        "networkd-dispatcher.service",
        "systemd-networkd.service",
        "systemd-networkd-wait-online.service",
        "iwd.service",
        "wpa_supplicant.service",
        "polkit.service",
        "polkitd.service",
        "gdm.service",
        "gdm3.service",
        "sddm.service",
        "lightdm.service",
        "ly.service",
        "greetd.service",
        "display-manager.service",
        "emergency.service",
        "rescue.service",
        "ctrl-alt-del.target",
    }
)
ESSENTIAL_UNIT_PREFIXES = (
    "systemd-",
    "initrd-",
    "dracut-",
    "plymouth",
    "kmod",
    "udev",
    "dbus",
    "getty@",
    "serial-getty@",
    "console-getty",
    "autovt@",
    "user@",
    "user-runtime-dir@",
    "modprobe@",
    "lvm2",
    "cryptsetup",
    "systemd-fsck",
)

_cache_lock = threading.Lock()
_cache: dict[str, Any] = {"key": None, "expires": 0.0, "payload": None}
_boot_lock = threading.Lock()
_boot_cache: dict[str, Any] = {"key": None, "expires": 0.0, "payload": None}
_units_lock = threading.Lock()
_units_cache: dict[str, Any] = {"expires": 0.0, "payload": None}
_svc_lock = threading.Lock()
_svc_cache: dict[str, Any] = {"key": None, "expires": 0.0, "payload": None}
_machine_lock = threading.Lock()
_machine_cache: dict[str, Any] = {"expires": 0.0, "payload": None}
_tips_lock = threading.Lock()
_tips_cache: dict[str, dict[str, Any]] = {}
_chat_lock = threading.Lock()
_ai_chats: dict[str, dict[str, Any]] = {}
_hosts_lock = threading.Lock()
_hosts_health: dict[str, dict[str, Any]] = {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


_REMOTE_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


HTTP_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)


class AiError(RuntimeError):
    def __init__(self, message: str, status: int = 0, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def system_boot_time() -> datetime:
    try:
        with open("/proc/stat", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("btime "):
                    return datetime.fromtimestamp(int(line.split()[1]), tz=timezone.utc)
    except OSError:
        pass
    return now_utc()


def iso(ts: datetime | None) -> str | None:
    if ts is None:
        return None
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_priority(value: Any) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 6
    return n if 0 <= n <= 7 else 6


def parse_realtime(value: Any) -> datetime | None:
    try:
        micros = int(value)
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def coerce_message(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        try:
            return bytes(int(x) & 0xFF for x in value).decode("utf-8", errors="replace")
        except Exception:
            return " ".join(str(x) for x in value)
    return str(value)


def unit_of(entry: dict[str, Any]) -> str:
    for key in ("_SYSTEMD_UNIT", "UNIT", "SYSLOG_IDENTIFIER", "_COMM"):
        val = entry.get(key)
        if val:
            return str(val)
    transport = str(entry.get("_TRANSPORT") or "")
    if transport == "kernel":
        return "kernel"
    return "desconhecido"


def app_of(unit: str, entry: dict[str, Any]) -> str:
    comm = str(entry.get("_COMM") or "").strip()
    ident = str(entry.get("SYSLOG_IDENTIFIER") or "").strip()
    generic = unit.startswith("user@") or unit.startswith("session-") or unit in {"init.scope", "desconhecido"}
    if generic:
        return comm or ident or unit.replace(".service", "")
    if unit.endswith(".service"):
        return unit[:-8]
    if unit == "kernel":
        return "kernel"
    return comm or ident or unit


def unit_weight(unit: str) -> float:
    if unit in CRITICAL_UNITS:
        return CRITICAL_UNITS[unit]
    if unit.endswith(".service") and unit.startswith("systemd"):
        return 1.3
    if unit == "kernel":
        return 1.55
    return 1.0


def keyword_boost(message: str) -> tuple[float, list[str]]:
    tags: list[str] = []
    boost = 1.0
    for pattern, factor, tag in IMPACT_KEYWORDS:
        if pattern.search(message):
            boost = max(boost, factor)
            tags.append(tag)
    return boost, tags


def fingerprint(message: str, unit: str, priority: int) -> tuple[str, str]:
    text = " ".join(message.split())
    if text.lower().startswith("audit:") or "apparmor=" in text.lower():
        kind_m = RE_AUDIT_TYPE.search(text)
        op_m = RE_AUDIT_OP.search(text)
        profile_m = RE_AUDIT_PROFILE.search(text)
        kind = kind_m.group(1) if kind_m else "audit"
        operation = op_m.group(1) if op_m else "evento"
        profile = profile_m.group(1) if profile_m else "*"
        title = f"audit {kind}: {operation} ({profile})"
        raw = f"audit|{kind}|{operation}|{profile}|{unit}|{min(priority, 4)}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16], title

    failed = RE_FAILED_UNIT.search(text)
    if failed:
        title = f"Falha ao iniciar {failed.group(1)}"
        raw = f"failed-unit|{failed.group(1).lower()}|{unit}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16], title

    readable = RE_UUID.sub("<uuid>", text)
    readable = RE_HEX.sub("<hex>", readable)
    readable = RE_MAC.sub("<mac>", readable)
    readable = RE_IPV4.sub("<ip>", readable)
    readable = RE_PID.sub("[pid]", readable)
    title = readable[:180] if readable else "(sem mensagem)"
    normalized = RE_NUM.sub("N", readable.lower())
    raw = f"{unit}|{min(priority, 5)}|{normalized[:240]}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16], title


def bucket_size(span_sec: float) -> int:
    if span_sec <= 3600:
        return 5 * 60
    if span_sec <= 6 * 3600:
        return 15 * 60
    if span_sec <= 24 * 3600:
        return 60 * 60
    if span_sec <= 3 * 24 * 3600:
        return 3 * 3600
    return 6 * 3600


def health_from_counts(counts: dict[str, int], span_hours: float) -> tuple[int, str]:
    hours = max(span_hours, 0.25)
    crit = counts.get("emerg", 0) + counts.get("alert", 0) + counts.get("crit", 0)
    err = counts.get("err", 0)
    warn = counts.get("warning", 0)
    score = 100.0
    score -= min(38.0, (crit / hours) * 14.0 + crit * 2.5)
    score -= min(28.0, (err / hours) * 1.15 + err * 0.08)
    score -= min(16.0, (warn / hours) * 0.12)
    score = max(8.0, min(100.0, score))
    value = int(round(score))
    if value >= 88:
        return value, "saudável"
    if value >= 70:
        return value, "atenção"
    if value >= 50:
        return value, "degradado"
    return value, "crítico"


def beacon_state(kind: str, value: float) -> str:
    if kind == "health":
        if value >= 88:
            return "ok"
        if value >= 70:
            return "warn"
        return "bad"
    if kind == "crit":
        return "ok" if value <= 0 else "bad"
    if kind == "err":
        if value <= 4:
            return "ok"
        if value <= 40:
            return "warn"
        return "bad"
    if value <= 20:
        return "ok"
    if value <= 120:
        return "warn"
    return "bad"


def impact_label(score: float, ceiling: float, priority: int) -> str:
    if ceiling <= 0:
        return "baixo"
    ratio = score / ceiling
    if priority <= 2:
        return "crítico"
    if priority == 3:
        return "alto" if ratio >= 0.22 else "médio"
    if priority == 4:
        return "médio" if ratio >= 0.45 else "baixo"
    return "baixo"


def collect_journal(since_key: str, lines: int, user_only: bool, boot: int | None = None) -> tuple[list[dict[str, Any]], str | None]:
    since_spec, _ = SINCE_MAP[since_key]
    cmd = ["journalctl", "--output=json", "--no-pager", f"--lines={lines}"]
    if boot is not None:
        cmd.append(f"--boot={boot}")
    elif since_key == "boot":
        cmd.append("--boot")
    else:
        cmd.extend(["--since", since_spec or "1 day ago"])
    if user_only:
        cmd.append("--user")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=90,
            check=False,
        )
    except FileNotFoundError:
        return [], "journalctl não encontrado neste sistema."
    except subprocess.TimeoutExpired:
        return [], "journalctl demorou demais para responder."

    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 and not proc.stdout:
        return [], stderr or f"journalctl saiu com código {proc.returncode}."

    entries: list[dict[str, Any]] = []
    for raw in proc.stdout.splitlines():
        if not raw.strip():
            continue
        try:
            entries.append(json.loads(raw))
        except json.JSONDecodeError:
            continue

    warning = None
    if proc.returncode != 0 and entries:
        warning = stderr or "journalctl retornou avisos, mas alguns eventos foram lidos."
    elif not entries and stderr:
        warning = stderr
    return entries, warning


def demo_entries() -> list[dict[str, Any]]:
    now = int(time.time() * 1_000_000)
    samples = [
        (3, "nginx.service", "nginx", "connect() failed (111: Connection refused) while connecting to upstream"),
        (3, "nginx.service", "nginx", "connect() failed (111: Connection refused) while connecting to upstream"),
        (3, "nginx.service", "nginx", "worker process 1842 exited on signal 11 (core dumped)"),
        (4, "NetworkManager.service", "NetworkManager", "device enp3s0: link is down"),
        (4, "NetworkManager.service", "NetworkManager", "device enp3s0: link is down"),
        (2, "kernel", "kernel", "Out of memory: Killed process 2201 (node) total-vm:8192000kB"),
        (3, "docker.service", "dockerd", "handler for POST /v1.43/containers/create returned error: no space left on device"),
        (3, "sshd.service", "sshd", "Failed password for root from 203.0.113.18 port 53221 ssh2"),
        (4, "systemd", "systemd", "Failed to start snapd.service"),
        (5, "kernel", "kernel", 'audit: type=1400 operation="open" profile="firefox" name="/etc/shadow"'),
        (6, "cron.service", "cron", "pam_unix(cron:session): session opened for user root"),
        (3, "postgres.service", "postgres", "could not write to file pg_wal/0000000100000000000000A1: No space left on device"),
        (4, "systemd-resolved.service", "systemd-resolved", "Timed out waiting for DNS server 1.1.1.1"),
        (3, "containerd.service", "containerd", "shim disconnected: container 9f3a2c aborted"),
    ]
    entries = []
    for i in range(180):
        pri, unit, comm, msg = samples[i % len(samples)]
        jitter = (i * 7 * 60 + (i * 13) % 40) * 1_000_000
        entries.append(
            {
                "PRIORITY": str(pri),
                "MESSAGE": msg if i % 11 else f"{msg} id={1000 + i}",
                "_SYSTEMD_UNIT": unit,
                "_COMM": comm,
                "SYSLOG_IDENTIFIER": comm,
                "__REALTIME_TIMESTAMP": str(now - jitter),
            }
        )
    return entries


def build_report(
    entries: list[dict[str, Any]],
    since_key: str,
    warning: str | None,
    source: str,
) -> dict[str, Any]:
    parsed: list[dict[str, Any]] = []
    sev_counts = {meta["id"]: 0 for meta in PRIORITY_META.values()}

    for raw in entries:
        message = coerce_message(raw.get("MESSAGE"))
        if not message.strip():
            continue
        priority = parse_priority(raw.get("PRIORITY"))
        ts = parse_realtime(raw.get("__REALTIME_TIMESTAMP")) or now_utc()
        unit = unit_of(raw)
        app = app_of(unit, raw)
        fp, title = fingerprint(message, unit, priority)
        boost, tags = keyword_boost(message)
        meta = PRIORITY_META[priority]
        parsed.append(
            {
                "priority": priority,
                "severity": meta["id"],
                "ts": ts,
                "unit": unit,
                "app": app,
                "message": message[:500],
                "fp": fp,
                "title": title,
                "boost": boost,
                "tags": tags,
                "weight": meta["weight"],
            }
        )
        sev_counts[meta["id"]] += 1

    parsed.sort(key=lambda e: e["ts"])
    total = len(parsed)
    if total == 0:
        return empty_report(since_key, warning, source)

    t0, t1 = parsed[0]["ts"], parsed[-1]["ts"]
    span_sec = max((t1 - t0).total_seconds(), 60.0)
    span_hours = span_sec / 3600.0
    step = bucket_size(span_sec)
    origin = int(t0.timestamp()) // step * step
    end = int(t1.timestamp())
    buckets: list[int] = []
    cursor = origin
    while cursor <= end:
        buckets.append(cursor)
        cursor += step
    if not buckets:
        buckets = [origin]

    timeline = [
        {"t": datetime.fromtimestamp(b, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "counts": {k: 0 for k in sev_counts}}
        for b in buckets
    ]
    index_of = {b: i for i, b in enumerate(buckets)}

    groups: dict[str, dict[str, Any]] = {}
    units: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "impact": 0.0, "err": 0, "warn": 0, "crit": 0, "apps": defaultdict(int), "restarts": 0}
    )
    oom_events: list[dict[str, Any]] = []
    restart_units: dict[str, int] = defaultdict(int)

    for event in parsed:
        bucket = int(event["ts"].timestamp()) // step * step
        if bucket in index_of:
            timeline[index_of[bucket]]["counts"][event["severity"]] += 1

        impact = event["weight"] * event["boost"] * unit_weight(event["unit"])
        u = units[event["unit"]]
        u["count"] += 1
        u["impact"] += impact
        u["apps"][event["app"]] += 1
        if event["priority"] <= 2:
            u["crit"] += 1
        elif event["priority"] == 3:
            u["err"] += 1
        if event["priority"] == 4:
            u["warn"] += 1

        restart = RE_RESTART_JOB.search(event["message"])
        if restart:
            name = restart.group(1).strip()
            restart_units[name] += 1
            units[name]["restarts"] += 1
        oom_name = None
        killed = RE_OOM_KILL.search(event["message"])
        if killed:
            oom_name = killed.group(2)
        else:
            task = RE_OOM_TASK.search(event["message"])
            if task:
                oom_name = task.group(1)
            elif "out of memory" in event["message"].lower() or "oom-kill" in event["message"].lower():
                oom_name = event["app"]
        if oom_name:
            oom_events.append(
                {
                    "t": iso(event["ts"]),
                    "proc": oom_name,
                    "pid": int(killed.group(1)) if killed else None,
                    "message": event["message"][:220],
                    "unit": event["unit"],
                }
            )

        grp = groups.get(event["fp"])
        if grp is None:
            grp = {
                "id": event["fp"],
                "title": event["title"],
                "sample": event["message"],
                "count": 0,
                "severity": event["severity"],
                "priority": event["priority"],
                "unit": event["unit"],
                "app": event["app"],
                "impact": 0.0,
                "tags": set(),
                "first": event["ts"],
                "last": event["ts"],
                "samples": [],
                "trend": [0] * min(12, len(buckets)),
            }
            groups[event["fp"]] = grp
        grp["count"] += 1
        grp["impact"] += impact
        grp["last"] = event["ts"]
        if event["ts"] < grp["first"]:
            grp["first"] = event["ts"]
        if event["priority"] < grp["priority"]:
            grp["priority"] = event["priority"]
            grp["severity"] = event["severity"]
            grp["sample"] = event["message"]
        grp["tags"].update(event["tags"])
        grp["samples"].append({"t": iso(event["ts"]), "message": event["message"], "severity": event["severity"]})
        if len(grp["samples"]) > 8:
            grp["samples"] = grp["samples"][-8:]
        if grp["count"] == 1 or event["priority"] <= grp["priority"]:
            grp["unit"] = event["unit"]
            grp["app"] = event["app"]

    for event in parsed:
        grp = groups[event["fp"]]
        span = max((grp["last"] - grp["first"]).total_seconds(), 1.0)
        slot = int(((event["ts"] - grp["first"]).total_seconds() / span) * (len(grp["trend"]) - 1))
        grp["trend"][max(0, min(slot, len(grp["trend"]) - 1))] += 1

    issues = sorted(groups.values(), key=lambda g: g["impact"], reverse=True)
    ceiling = issues[0]["impact"] if issues else 1.0
    noisy = sev_counts["info"] + sev_counts["debug"] + sev_counts["notice"]
    problem_total = max(1, total - noisy)
    health, health_label = health_from_counts(sev_counts, span_hours)

    fixable = [i for i in issues if i["priority"] <= 4]
    fixable_impact = sum(i["impact"] for i in fixable) or 1.0
    lost = 100 - health
    improvement_total = round(min(42.0, lost * 0.78), 1)

    issue_rows = []
    for item in issues[:80]:
        pct = round(100.0 * item["count"] / total, 2)
        err_pct = round(100.0 * item["count"] / problem_total, 2) if item["priority"] <= 4 else 0.0
        share = item["impact"] / fixable_impact if item["priority"] <= 4 else 0.0
        improvement = round(improvement_total * share, 2) if item["priority"] <= 4 else 0.0
        issue_rows.append(
            {
                "id": item["id"],
                "title": item["title"],
                "sample": item["sample"],
                "count": item["count"],
                "pct": pct,
                "problem_pct": err_pct,
                "severity": item["severity"],
                "priority": item["priority"],
                "severity_label": PRIORITY_META[item["priority"]]["label"],
                "unit": item["unit"],
                "app": item["app"],
                "impact": round(item["impact"], 1),
                "impact_label": impact_label(item["impact"], ceiling, item["priority"]),
                "improvement_pct": improvement,
                "tags": sorted(item["tags"]),
                "first_seen": iso(item["first"]),
                "last_seen": iso(item["last"]),
                "samples": item["samples"],
                "trend": item["trend"],
                "boot_status": "unknown",
                "boot_label": "sem diff de boot",
                "context": None,
            }
        )

    unit_rows = []
    for name, data in units.items():
        app = max(data["apps"], key=data["apps"].get)
        if data["crit"]:
            state = "bad"
        elif data["err"]:
            state = "warn"
        else:
            state = "ok"
        unit_rows.append(
            {
                "unit": name,
                "app": app,
                "count": data["count"],
                "pct": round(100.0 * data["count"] / total, 2),
                "impact": round(data["impact"], 1),
                "crit": data["crit"],
                "err": data["err"],
                "warn": data["warn"],
                "restarts": data["restarts"],
                "state": state,
            }
        )
    unit_rows.sort(key=lambda r: r["impact"], reverse=True)

    severity_rows = []
    for level in range(8):
        meta = PRIORITY_META[level]
        count = sev_counts[meta["id"]]
        severity_rows.append(
            {
                "id": meta["id"],
                "label": meta["label"],
                "count": count,
                "pct": round(100.0 * count / total, 2) if total else 0.0,
            }
        )

    error_count = sev_counts["emerg"] + sev_counts["alert"] + sev_counts["crit"] + sev_counts["err"]
    warn_count = sev_counts["warning"]
    crit_count = sev_counts["emerg"] + sev_counts["alert"] + sev_counts["crit"]
    cutoff_15 = now_utc() - timedelta(minutes=15)
    errors_15m = 0
    for point in timeline:
        try:
            ts = datetime.fromisoformat(point["t"].replace("Z", "+00:00"))
        except ValueError:
            continue
        if ts < cutoff_15:
            continue
        counts = point["counts"]
        errors_15m += counts.get("emerg", 0) + counts.get("alert", 0) + counts.get("crit", 0) + counts.get("err", 0)

    oom_compact = []
    seen_oom: set[tuple[str, str]] = set()
    for event in reversed(oom_events):
        key = (event["proc"], event["t"][:16])
        if key in seen_oom:
            continue
        seen_oom.add(key)
        oom_compact.append(event)
        if len(oom_compact) >= 8:
            break
    oom_compact.reverse()

    return {
        "version": VERSION,
        "generated_at": iso(now_utc()),
        "since": since_key,
        "since_label": SINCE_MAP[since_key][1],
        "source": source,
        "warning": warning,
        "truncated": total >= DEFAULT_LINES * 0.98,
        "stats": {
            "total": total,
            "errors": error_count,
            "warnings": warn_count,
            "critical": crit_count,
            "unique_issues": len(issues),
            "units": len(units),
            "health": health,
            "health_label": health_label,
            "improvement_potential": improvement_total,
            "span_hours": round(span_hours, 2),
            "hostname": socket.gethostname(),
            "errors_15m": errors_15m,
            "oom": len(oom_events),
            "failed_units": 0,
            "new_this_boot": 0,
        },
        "beacons": [
            {"id": "health", "label": "Sistema", "state": beacon_state("health", health), "value": health, "hint": health_label},
            {"id": "crit", "label": "Crítico", "state": beacon_state("crit", crit_count), "value": crit_count, "hint": "emerg/alert/crit"},
            {"id": "err", "label": "Erros", "state": beacon_state("err", error_count), "value": error_count, "hint": "prioridade ≤ erro"},
            {"id": "warn", "label": "Avisos", "state": beacon_state("warn", warn_count), "value": warn_count, "hint": "warning"},
            {"id": "boot", "label": "Este boot", "state": "ok", "value": 0, "hint": "problemas novos"},
            {"id": "units", "label": "Unidades", "state": "ok", "value": 0, "hint": "falhas systemd"},
        ],
        "severity": severity_rows,
        "timeline": timeline,
        "units": unit_rows[:18],
        "issues": issue_rows,
        "apps": aggregate_apps(unit_rows),
        "failed_units": [],
        "boot_diff": {
            "has_previous": False,
            "boot_at": iso(system_boot_time()),
            "new_count": 0,
            "still_count": 0,
            "gone_count": 0,
            "new": [],
            "still": [],
        },
        "oom": {"count": len(oom_events), "events": oom_compact},
        "restarts": [
            {"unit": name, "count": count}
            for name, count in sorted(restart_units.items(), key=lambda item: item[1], reverse=True)[:12]
        ],
    }


def aggregate_apps(unit_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    apps: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "impact": 0.0, "state": "ok"})
    for row in unit_rows:
        app = row["app"]
        apps[app]["count"] += row["count"]
        apps[app]["impact"] += row["impact"]
        rank = {"ok": 0, "warn": 1, "bad": 2}
        if rank[row["state"]] > rank[apps[app]["state"]]:
            apps[app]["state"] = row["state"]
    out = [{"app": name, **data, "impact": round(data["impact"], 1)} for name, data in apps.items()]
    out.sort(key=lambda r: r["impact"], reverse=True)
    return out[:12]


def empty_report(since_key: str, warning: str | None, source: str) -> dict[str, Any]:
    return {
        "version": VERSION,
        "generated_at": iso(now_utc()),
        "since": since_key,
        "since_label": SINCE_MAP[since_key][1],
        "source": source,
        "warning": warning or "Nenhum evento encontrado no período.",
        "truncated": False,
        "stats": {
            "total": 0,
            "errors": 0,
            "warnings": 0,
            "critical": 0,
            "unique_issues": 0,
            "units": 0,
            "health": 100,
            "health_label": "saudável",
            "improvement_potential": 0,
            "span_hours": 0,
            "hostname": socket.gethostname(),
            "errors_15m": 0,
            "oom": 0,
            "failed_units": 0,
            "new_this_boot": 0,
        },
        "beacons": [
            {"id": "health", "label": "Sistema", "state": "ok", "value": 100, "hint": "sem eventos"},
            {"id": "crit", "label": "Crítico", "state": "ok", "value": 0, "hint": "emerg/alert/crit"},
            {"id": "err", "label": "Erros", "state": "ok", "value": 0, "hint": "prioridade ≤ erro"},
            {"id": "warn", "label": "Avisos", "state": "ok", "value": 0, "hint": "warning"},
            {"id": "boot", "label": "Este boot", "state": "ok", "value": 0, "hint": "problemas novos"},
            {"id": "units", "label": "Unidades", "state": "ok", "value": 0, "hint": "falhas systemd"},
        ],
        "severity": [
            {"id": PRIORITY_META[i]["id"], "label": PRIORITY_META[i]["label"], "count": 0, "pct": 0.0}
            for i in range(8)
        ],
        "timeline": [],
        "units": [],
        "issues": [],
        "apps": [],
        "failed_units": [],
        "boot_diff": {
            "has_previous": False,
            "boot_at": iso(system_boot_time()),
            "new_count": 0,
            "still_count": 0,
            "gone_count": 0,
            "new": [],
            "still": [],
        },
        "oom": {"count": 0, "events": []},
        "restarts": [],
    }


def get_report(since_key: str, lines: int, user_only: bool, demo: bool) -> dict[str, Any]:
    if since_key not in SINCE_MAP:
        since_key = "24h"
    cache_key = f"{since_key}|{lines}|{user_only}|{demo}"
    now = time.time()
    with _cache_lock:
        if _cache["key"] == cache_key and now < _cache["expires"]:
            return _cache["payload"]

    if demo:
        entries, warning, source = demo_entries(), None, "demo"
    else:
        entries, warning = collect_journal(since_key, lines, user_only)
        source = "journalctl --user" if user_only else "journalctl"
        if not entries and not user_only and not warning:
            fallback, fb_warn = collect_journal(since_key, lines, True)
            if fallback:
                entries, warning, source = fallback, fb_warn, "journalctl --user"
                warning = "Sem acesso ao journal do sistema; usando o journal do usuário."

    payload = build_report(entries, since_key, warning, source)
    enrich_report(payload, user_only=user_only, demo=demo)
    with _cache_lock:
        _cache["key"] = cache_key
        _cache["expires"] = time.time() + CACHE_TTL_SEC
        _cache["payload"] = payload
    return payload


def _systemctl_show(unit: str, user_only: bool = False, extra: tuple[str, ...] = ()) -> dict[str, str]:
    fields = (
        "Id",
        "ActiveState",
        "SubState",
        "NRestarts",
        "Result",
        "Description",
        "ExecMainStatus",
        "ExecMainCode",
        "UnitFileState",
        "RefuseManualStop",
        "WantedBy",
        "RequiredBy",
        "FragmentPath",
        *extra,
    )
    cmd = ["systemctl", "--no-ask-password", "show", unit]
    if user_only:
        cmd.append("--user")
    for prop in fields:
        cmd.extend(["-p", prop])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=4, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    info: dict[str, str] = {}
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        key, _, value = line.partition("=")
        if key:
            info[key] = value
    return info


def collect_failed_units(demo: bool = False) -> list[dict[str, Any]]:
    if demo:
        return [
            {
                "unit": "snapd.service",
                "active": "failed",
                "sub": "failed",
                "restarts": 6,
                "result": "timeout",
                "description": "Snap Daemon",
            },
            {
                "unit": "docker.service",
                "active": "failed",
                "sub": "failed",
                "restarts": 3,
                "result": "exit-code",
                "description": "Docker Application Container Engine",
            },
        ]
    now = time.time()
    with _units_lock:
        if now < float(_units_cache.get("expires") or 0) and _units_cache.get("payload") is not None:
            return list(_units_cache["payload"])
    rows: list[dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"],
            capture_output=True,
            timeout=6,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    for raw in proc.stdout.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("UNIT"):
            continue
        parts = line.split()
        if not parts:
            continue
        if parts[0] in {"●", "*", "○"}:
            parts = parts[1:]
        if not parts:
            continue
        unit = parts[0]
        if unit.endswith(":"):
            continue
        info = _systemctl_show(unit, user_only=False)
        try:
            restarts = int(info.get("NRestarts") or 0)
        except ValueError:
            restarts = 0
        rows.append(
            {
                "unit": info.get("Id") or unit,
                "active": info.get("ActiveState") or (parts[2] if len(parts) > 2 else "failed"),
                "sub": info.get("SubState") or (parts[3] if len(parts) > 3 else "failed"),
                "restarts": restarts,
                "result": info.get("Result") or "",
                "description": info.get("Description") or " ".join(parts[4:]),
            }
        )
        if len(rows) >= 16:
            break
    with _units_lock:
        _units_cache["expires"] = time.time() + 20
        _units_cache["payload"] = rows
    return rows


def _safe_unit_name(value: Any) -> str:
    name = str(value or "").strip()
    if not name or not RE_UNIT_SAFE.match(name):
        return ""
    return name


def is_essential_unit(unit: str, info: dict[str, str] | None = None) -> bool:
    name = (unit or "").strip().lower()
    if not name:
        return True
    if not name.endswith(".service"):
        return True
    if name in ESSENTIAL_UNIT_NAMES:
        return True
    if any(name.startswith(prefix) for prefix in ESSENTIAL_UNIT_PREFIXES):
        return True
    if info:
        if str(info.get("RefuseManualStop") or "").lower() in {"yes", "1", "true"}:
            return True
        wanted = f"{info.get('WantedBy') or ''} {info.get('RequiredBy') or ''}".lower()
        if "sysinit.target" in wanted or "shutdown.target" in wanted:
            return True
    return False


def can_disable_unit(unit: str, info: dict[str, str] | None = None, failed: bool = False) -> bool:
    if not failed or is_essential_unit(unit, info):
        return False
    if not (unit or "").endswith(".service"):
        return False
    state = str((info or {}).get("UnitFileState") or "").lower()
    if state in {"static", "generated", "transient", "alias"}:
        return False
    return True


def unit_state_bucket(active: str, sub: str) -> str:
    active = (active or "").lower()
    sub = (sub or "").lower()
    if active == "failed" or sub == "failed":
        return "failed"
    if active == "activating":
        return "starting"
    if active == "active" and sub == "running":
        return "running"
    if active == "active":
        return "active"
    if active in {"inactive", "deactivating"} or sub in {"dead", "exited"}:
        return "stopped"
    return "other"


def _decorate_service(row: dict[str, Any]) -> dict[str, Any]:
    bucket = unit_state_bucket(str(row.get("active") or ""), str(row.get("sub") or ""))
    lamp = "ok"
    if bucket == "failed":
        lamp = "bad"
    elif bucket in {"starting", "active"}:
        lamp = "warn"
    elif bucket == "stopped":
        lamp = "ok"
    row["bucket"] = bucket
    row["lamp"] = lamp
    row["essential"] = is_essential_unit(str(row.get("unit") or ""))
    row["can_disable"] = can_disable_unit(str(row.get("unit") or ""), failed=(bucket == "failed"))
    return row


def _units_payload(rows: list[dict[str, Any]]) -> dict[str, Any]:
    decorated = [_decorate_service(dict(row)) for row in rows]
    rank = {"failed": 0, "starting": 1, "running": 2, "active": 3, "stopped": 4, "other": 5}
    decorated.sort(key=lambda row: (rank.get(row["bucket"], 9), row["unit"].lower()))
    counts = {"running": 0, "stopped": 0, "failed": 0, "active": 0, "starting": 0, "other": 0}
    for row in decorated:
        counts[row["bucket"]] = counts.get(row["bucket"], 0) + 1
    return {
        "version": VERSION,
        "total": len(decorated),
        "counts": counts,
        "units": decorated[:500],
    }


def demo_service_units() -> dict[str, Any]:
    rows = [
        {"unit": "nginx.service", "load": "loaded", "active": "active", "sub": "running", "description": "A high performance web server"},
        {"unit": "postgres.service", "load": "loaded", "active": "active", "sub": "running", "description": "PostgreSQL RDBMS"},
        {"unit": "sshd.service", "load": "loaded", "active": "active", "sub": "running", "description": "OpenSSH server daemon"},
        {"unit": "cron.service", "load": "loaded", "active": "active", "sub": "running", "description": "Regular background program processing daemon"},
        {"unit": "docker.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Docker Application Container Engine"},
        {"unit": "snapd.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "Snap Daemon"},
        {"unit": "apport-autoreport.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Process error reports"},
        {"unit": "systemd-resolved.service", "load": "loaded", "active": "active", "sub": "running", "description": "Network Name Resolution"},
        {"unit": "NetworkManager.service", "load": "loaded", "active": "active", "sub": "running", "description": "Network Manager"},
        {"unit": "bluetooth.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "Bluetooth service"},
        {"unit": "containerd.service", "load": "loaded", "active": "active", "sub": "running", "description": "containerd container runtime"},
        {"unit": "cups.service", "load": "loaded", "active": "active", "sub": "exited", "description": "CUPS Scheduler"},
    ]
    return _units_payload(rows)


def _parse_systemctl_units_plain(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.upper().startswith("UNIT "):
            continue
        parts = line.split()
        if not parts:
            continue
        if parts[0] in {"●", "*", "○", "×", "x"}:
            parts = parts[1:]
        if len(parts) < 4:
            continue
        unit = parts[0]
        if unit.endswith(":") or not RE_UNIT_SAFE.match(unit):
            continue
        rows.append(
            {
                "unit": unit,
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": " ".join(parts[4:]),
            }
        )
        if len(rows) >= 500:
            break
    return rows


def collect_service_units(user_only: bool = False, demo: bool = False) -> dict[str, Any]:
    if demo:
        return demo_service_units()
    key = "user" if user_only else "system"
    now = time.time()
    with _svc_lock:
        cached = _svc_cache.get("payload")
        if _svc_cache.get("key") == key and now < float(_svc_cache.get("expires") or 0) and isinstance(cached, dict):
            return cached
    cmd = ["systemctl", "--no-ask-password", "list-units", "--type=service", "--all", "--no-pager"]
    if user_only:
        cmd.append("--user")
    rows: list[dict[str, Any]] = []
    try:
        proc = subprocess.run(cmd + ["--output=json"], capture_output=True, timeout=10, check=False)
        stdout = proc.stdout.lstrip()
        if proc.returncode == 0 and stdout.startswith(b"["):
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                data = []
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    unit = _safe_unit_name(item.get("unit") or item.get("Unit") or item.get("id"))
                    if not unit:
                        continue
                    rows.append(
                        {
                            "unit": unit,
                            "load": str(item.get("load") or item.get("Load") or ""),
                            "active": str(item.get("active") or item.get("ActiveState") or item.get("active_state") or ""),
                            "sub": str(item.get("sub") or item.get("SubState") or item.get("sub_state") or ""),
                            "description": str(item.get("description") or item.get("Description") or ""),
                        }
                    )
                    if len(rows) >= 500:
                        break
        if not rows:
            proc = subprocess.run(cmd + ["--plain", "--no-legend"], capture_output=True, timeout=10, check=False)
            rows = _parse_systemctl_units_plain(proc.stdout.decode("utf-8", errors="replace"))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        rows = []
    payload = _units_payload(rows)
    with _svc_lock:
        _svc_cache["key"] = key
        _svc_cache["expires"] = time.time() + 8
        _svc_cache["payload"] = payload
    return payload


def _journalctl_since_args(since_key: str) -> list[str]:
    since_spec, _ = SINCE_MAP.get(since_key, SINCE_MAP["24h"])
    if since_key == "boot":
        return ["--boot"]
    return ["--since", since_spec or "1 day ago"]


def _log_entry_from_raw(raw: dict[str, Any]) -> dict[str, Any] | None:
    message = coerce_message(raw.get("MESSAGE")).strip()
    if not message:
        return None
    priority = parse_priority(raw.get("PRIORITY"))
    ts = parse_realtime(raw.get("__REALTIME_TIMESTAMP")) or now_utc()
    ident = str(raw.get("SYSLOG_IDENTIFIER") or raw.get("_COMM") or "")[:80]
    pid = str(raw.get("_PID") or raw.get("SYSLOG_PID") or "")
    return {
        "t": iso(ts),
        "priority": priority,
        "severity": PRIORITY_META[priority]["id"],
        "ident": ident,
        "pid": pid,
        "unit": unit_of(raw),
        "message": message[:800],
    }


def _with_unit_policy(payload: dict[str, Any], user_only: bool, demo: bool) -> dict[str, Any]:
    unit = str(payload.get("unit") or "")
    info: dict[str, str] = {}
    failed = False
    if demo:
        for row in demo_service_units().get("units") or []:
            if row.get("unit") == unit:
                info = {
                    "ActiveState": str(row.get("active") or ""),
                    "SubState": str(row.get("sub") or ""),
                    "Description": str(row.get("description") or ""),
                    "UnitFileState": "enabled",
                    "Result": "exit-code" if row.get("bucket") == "failed" else "success",
                    "ExecMainStatus": "1" if row.get("bucket") == "failed" else "0",
                    "FragmentPath": f"/lib/systemd/system/{unit}",
                }
                failed = row.get("bucket") == "failed"
                break
    elif unit:
        info = _systemctl_show(unit, user_only=user_only)
        failed = str(info.get("ActiveState") or "").lower() == "failed" or str(info.get("SubState") or "").lower() == "failed"
    payload["status"] = {
        "active": info.get("ActiveState") or "",
        "sub": info.get("SubState") or "",
        "result": info.get("Result") or "",
        "exec_status": info.get("ExecMainStatus") or "",
        "unit_file_state": info.get("UnitFileState") or "",
        "fragment": info.get("FragmentPath") or "",
        "description": info.get("Description") or "",
    }
    payload["failed"] = failed
    payload["essential"] = is_essential_unit(unit, info) if unit else True
    payload["can_disable"] = can_disable_unit(unit, info, failed=failed)
    return payload


def collect_unit_logs(
    unit: str,
    ident: str,
    since_key: str,
    lines: int,
    user_only: bool,
    demo: bool,
) -> dict[str, Any]:
    unit = _safe_unit_name(unit)
    ident = _safe_unit_name(ident)
    if since_key not in SINCE_MAP:
        since_key = "24h"
    lines = max(40, min(int(lines or 400), 1500))
    if not unit and not ident:
        return {"error": "missing_unit", "message": "Informe uma unidade systemd ou um identificador."}

    pretty = ["journalctl"]
    if unit == "kernel" or ident == "kernel":
        pretty.append("-k")
        selector = "kernel"
    elif unit:
        pretty.extend(["-u", unit])
        selector = unit
    else:
        pretty.extend(["-t", ident])
        selector = ident
    if since_key == "boot":
        pretty.append("--boot")
    else:
        pretty.extend(["--since", f'"{SINCE_MAP[since_key][0]}"'])
    pretty.extend(["-n", str(lines)])
    if user_only:
        pretty.append("--user")

    if demo:
        entries = []
        for raw in demo_entries():
            raw_unit = unit_of(raw)
            raw_app = app_of(raw_unit, raw)
            if unit and raw_unit != unit and f"{raw_app}.service" != unit:
                continue
            if ident and raw_app != ident and str(raw.get("SYSLOG_IDENTIFIER") or "") != ident:
                continue
            parsed = _log_entry_from_raw(raw)
            if parsed:
                entries.append(parsed)
        entries.sort(key=lambda row: row["t"] or "")
        return _with_unit_policy(
            {
                "unit": unit,
                "ident": ident,
                "selector": selector,
                "command": " ".join(pretty),
                "since": since_key,
                "since_label": SINCE_MAP[since_key][1],
                "count": len(entries[-lines:]),
                "warning": None,
                "entries": entries[-lines:],
            },
            user_only=user_only,
            demo=True,
        )

    cmd = ["journalctl", "--output=json", "--no-pager", f"--lines={lines}"]
    if unit == "kernel" or ident == "kernel":
        cmd.append("--dmesg")
    elif unit:
        cmd.extend(["--unit", unit])
    else:
        cmd.extend(["--identifier", ident])
    cmd.extend(_journalctl_since_args(since_key))
    if user_only:
        cmd.append("--user")

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=40, check=False)
    except FileNotFoundError:
        return {"error": "journalctl_missing", "message": "journalctl não encontrado neste sistema.", "command": " ".join(pretty)}
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "message": "journalctl demorou demais para responder.", "command": " ".join(pretty)}

    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    entries: list[dict[str, Any]] = []
    for raw_line in proc.stdout.splitlines():
        if not raw_line.strip():
            continue
        try:
            raw = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        parsed = _log_entry_from_raw(raw)
        if parsed:
            entries.append(parsed)
    warning = None
    if proc.returncode != 0 and not entries:
        warning = stderr or f"journalctl saiu com código {proc.returncode}."
    elif proc.returncode != 0:
        warning = stderr or "journalctl retornou avisos, mas alguns eventos foram lidos."
    elif not entries and stderr:
        warning = stderr
    entries.sort(key=lambda row: row["t"] or "")
    return _with_unit_policy(
        {
            "unit": unit,
            "ident": ident,
            "selector": selector,
            "command": " ".join(pretty),
            "since": since_key,
            "since_label": SINCE_MAP[since_key][1],
            "count": len(entries),
            "warning": warning,
            "entries": entries,
        },
        user_only=user_only,
        demo=False,
    )


def _boot_fingerprints(boot: int, lines: int, user_only: bool) -> dict[str, dict[str, Any]]:
    cmd = [
        "journalctl",
        "--output=json",
        "--no-pager",
        f"--lines={lines}",
        f"--boot={boot}",
        "--priority=0..4",
    ]
    if user_only:
        cmd.append("--user")
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=50, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    found: dict[str, dict[str, Any]] = {}
    for raw in proc.stdout.splitlines():
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        message = coerce_message(entry.get("MESSAGE"))
        if not message.strip():
            continue
        priority = parse_priority(entry.get("PRIORITY"))
        if priority > 4:
            continue
        unit = unit_of(entry)
        app = app_of(unit, entry)
        fp, title = fingerprint(message, unit, priority)
        row = found.get(fp)
        if row is None:
            found[fp] = {"id": fp, "title": title, "unit": unit, "app": app, "count": 1, "priority": priority}
        else:
            row["count"] += 1
            if priority < row["priority"]:
                row["priority"] = priority
                row["title"] = title
    return found


def collect_boot_diff(user_only: bool, demo: bool, issues: list[dict[str, Any]]) -> dict[str, Any]:
    boot_at = system_boot_time()
    if demo:
        new_ids = {row["id"] for row in issues[:4]}
        still = [row for row in issues[4:8]]
        return {
            "has_previous": True,
            "boot_at": iso(boot_at),
            "new_count": len(new_ids),
            "still_count": len(still),
            "gone_count": 3,
            "new": [
                {"id": row["id"], "title": row["title"], "app": row["app"], "count": row["count"]}
                for row in issues[:4]
            ],
            "still": [
                {"id": row["id"], "title": row["title"], "app": row["app"], "count": row["count"]}
                for row in still
            ],
            "new_ids": list(new_ids),
            "still_ids": [row["id"] for row in still],
        }
    key = f"{user_only}"
    now = time.time()
    with _boot_lock:
        if _boot_cache.get("key") == key and now < float(_boot_cache.get("expires") or 0):
            return dict(_boot_cache["payload"])
    current = _boot_fingerprints(0, 12_000, user_only)
    previous = _boot_fingerprints(-1, 12_000, user_only)
    has_previous = bool(previous)
    new_map = {fp: row for fp, row in current.items() if fp not in previous} if has_previous else dict(current)
    still_map = {fp: row for fp, row in current.items() if fp in previous} if has_previous else {}
    gone = max(0, len(previous) - len(still_map)) if has_previous else 0
    payload = {
        "has_previous": has_previous,
        "boot_at": iso(boot_at),
        "new_count": len(new_map),
        "still_count": len(still_map),
        "gone_count": gone,
        "new": sorted(new_map.values(), key=lambda row: row["count"], reverse=True)[:12],
        "still": sorted(still_map.values(), key=lambda row: row["count"], reverse=True)[:8],
        "new_ids": list(new_map),
        "still_ids": list(still_map),
    }
    with _boot_lock:
        _boot_cache["key"] = key
        _boot_cache["expires"] = time.time() + 90
        _boot_cache["payload"] = payload
    return dict(payload)


def attach_issue_flags(payload: dict[str, Any], boot_diff: dict[str, Any]) -> None:
    new_ids = set(boot_diff.get("new_ids") or [])
    still_ids = set(boot_diff.get("still_ids") or [])
    boot_at = system_boot_time()
    has_previous = bool(boot_diff.get("has_previous"))
    for issue in payload.get("issues") or []:
        first = None
        if issue.get("first_seen"):
            try:
                first = datetime.fromisoformat(str(issue["first_seen"]).replace("Z", "+00:00"))
            except ValueError:
                first = None
        after_boot = first is not None and first >= boot_at
        if has_previous and issue["id"] in new_ids:
            issue["boot_status"] = "new"
            issue["boot_label"] = "novo neste boot"
        elif has_previous and issue["id"] in still_ids:
            issue["boot_status"] = "recurring"
            issue["boot_label"] = "já no boot anterior"
        elif after_boot:
            issue["boot_status"] = "this_boot"
            issue["boot_label"] = "visto neste boot"
        else:
            issue["boot_status"] = "older"
            issue["boot_label"] = "já vinha de antes"
        issue["context"] = LIVE.nearest(issue.get("last_seen")) if "LIVE" in globals() else None


def journal_pulse() -> dict[str, Any]:
    with _cache_lock:
        report = _cache.get("payload")
    if not isinstance(report, dict):
        return {
            "state": "ok",
            "health": None,
            "errors_15m": 0,
            "failed": 0,
            "oom": 0,
            "oom_events": [],
            "new_boot": 0,
            "top": None,
        }
    stats = report.get("stats") or {}
    failed = len(report.get("failed_units") or [])
    oom_payload = report.get("oom") or {}
    oom = int(oom_payload.get("count") or 0)
    oom_events = list(oom_payload.get("events") or [])[-8:]
    new_boot = int((report.get("boot_diff") or {}).get("new_count") or 0)
    errors_15m = int(stats.get("errors_15m") or 0)
    health = stats.get("health")
    issues = report.get("issues") or []
    top = None
    if issues:
        top = {"title": issues[0].get("title"), "app": issues[0].get("app"), "id": issues[0].get("id")}
    state = "ok"
    if (health is not None and health < 50) or failed or oom:
        state = "bad"
    elif (health is not None and health < 88) or errors_15m >= 8 or new_boot >= 4:
        state = "warn"
    return {
        "state": state,
        "health": health,
        "errors_15m": errors_15m,
        "failed": failed,
        "oom": oom,
        "oom_events": oom_events,
        "new_boot": new_boot,
        "top": top,
    }


def enrich_report(payload: dict[str, Any], user_only: bool, demo: bool) -> None:
    failed = collect_failed_units(demo=demo)
    restart_names = {row["unit"]: row["count"] for row in payload.get("restarts") or []}
    for row in failed:
        if not row.get("restarts") and row["unit"] in restart_names:
            row["restarts"] = restart_names[row["unit"]]
    extra = [
        {
            "unit": name,
            "active": "activating",
            "sub": "auto-restart",
            "restarts": count,
            "result": "restart-loop",
            "description": "reinício agendado pelo systemd",
        }
        for name, count in restart_names.items()
        if count >= 3 and name not in {row["unit"] for row in failed}
    ]
    failed.extend(extra[:6])
    payload["failed_units"] = failed
    boot_diff = collect_boot_diff(user_only, demo, payload.get("issues") or [])
    attach_issue_flags(payload, boot_diff)
    payload["boot_diff"] = {k: v for k, v in boot_diff.items() if k not in {"new_ids", "still_ids"}}
    payload["stats"]["failed_units"] = len(failed)
    payload["stats"]["new_this_boot"] = int(boot_diff.get("new_count") or 0)
    payload["stats"]["oom"] = int((payload.get("oom") or {}).get("count") or 0)
    for beacon in payload.get("beacons") or []:
        if beacon["id"] == "boot":
            beacon["value"] = payload["stats"]["new_this_boot"]
            beacon["state"] = "ok" if beacon["value"] <= 2 else ("warn" if beacon["value"] <= 8 else "bad")
            beacon["hint"] = "problemas novos vs boot anterior" if boot_diff.get("has_previous") else "visto desde o boot"
        elif beacon["id"] == "units":
            beacon["value"] = len(failed)
            beacon["state"] = "ok" if not failed else "bad"
            beacon["hint"] = "systemctl --failed + restart loop"


def config_file(name: str) -> Path:
    current = CONFIG_DIR / name
    if current.is_file():
        return current
    legacy = LEGACY_CONFIG_DIR / name
    if legacy.is_file():
        return legacy
    return current


def write_config_file(name: str, text: str) -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path = CONFIG_DIR / name
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return path


def load_ai_config() -> dict[str, str]:
    path = config_file("ai.json")
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items() if v is not None}
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def save_ai_config(provider: str, api_key: str) -> None:
    write_config_file(
        "ai.json",
        json.dumps({"provider": provider, "api_key": api_key}, ensure_ascii=False),
    )


def clear_ai_config() -> None:
    for path in (CONFIG_DIR / "ai.json", LEGACY_CONFIG_DIR / "ai.json"):
        try:
            path.unlink(missing_ok=True)
        except TypeError:
            if path.exists():
                path.unlink()
        except OSError:
            pass


def clear_tips_cache() -> None:
    with _tips_lock:
        _tips_cache.clear()
    with _chat_lock:
        _ai_chats.clear()


def auth_required() -> bool:
    host = str((DashboardHandler.config or {}).get("bind_host") or DEFAULT_HOST).strip().lower()
    return host not in {"127.0.0.1", "localhost", "::1", ""}


def user_in_healthd_group(username: str) -> bool:
    try:
        grp_info = grp.getgrnam(AUTH_GROUP)
    except KeyError:
        return False
    if username in grp_info.gr_mem:
        return True
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return False
    return pw.pw_gid == grp_info.gr_gid


def user_may_web_login(username: str) -> bool:
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return False
    shell = os.path.basename(pw.pw_shell or "").lstrip("-")
    if shell in NOLOGIN_SHELLS:
        return False
    return user_in_healthd_group(username)


def pam_service_name() -> str:
    if Path("/etc/pam.d/healthd").is_file():
        return "healthd"
    if Path("/etc/pam.d/login").is_file():
        return "login"
    return "other"


def pam_authenticate(username: str, password: str) -> bool:
    libname = ctypes.util.find_library("pam") or "libpam.so.0"
    try:
        libpam = ctypes.CDLL(libname)
    except OSError:
        return False
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(libc_name)
    except OSError:
        return False
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]

    class PamHandle(ctypes.Structure):
        _fields_ = [("handle", ctypes.c_void_p)]

    class PamMessage(ctypes.Structure):
        _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]

    class PamResponse(ctypes.Structure):
        _fields_ = [("resp", ctypes.c_char_p), ("resp_retcode", ctypes.c_int)]

    conv_func = ctypes.CFUNCTYPE(
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.POINTER(PamMessage)),
        ctypes.POINTER(ctypes.POINTER(PamResponse)),
        ctypes.c_void_p,
    )

    class PamConv(ctypes.Structure):
        _fields_ = [("conv", conv_func), ("appdata_ptr", ctypes.c_void_p)]

    PAM_PROMPT_ECHO_OFF = 1
    PAM_PROMPT_ECHO_ON = 2
    password_bytes = password.encode("utf-8")
    username_bytes = username.encode("utf-8")

    @conv_func
    def conv(n_msg, msg, resp, _appdata):
        raw = libc.calloc(n_msg, ctypes.sizeof(PamResponse))
        if not raw:
            return 2
        ptr = ctypes.cast(raw, ctypes.POINTER(PamResponse))
        for i in range(n_msg):
            style = msg[i].contents.msg_style
            answer = b""
            if style == PAM_PROMPT_ECHO_OFF:
                answer = password_bytes
            elif style == PAM_PROMPT_ECHO_ON:
                answer = username_bytes
            if answer:
                dup = libc.strdup(answer)
                ptr[i].resp = ctypes.cast(dup, ctypes.c_char_p) if dup else None
            else:
                ptr[i].resp = None
            ptr[i].resp_retcode = 0
        resp[0] = ptr
        return 0

    handle = PamHandle()
    conversation = PamConv(conv, None)
    libpam.pam_start.restype = ctypes.c_int
    libpam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(PamConv), ctypes.POINTER(PamHandle)]
    libpam.pam_authenticate.restype = ctypes.c_int
    libpam.pam_acct_mgmt.restype = ctypes.c_int
    libpam.pam_end.restype = ctypes.c_int
    start = libpam.pam_start(pam_service_name().encode(), username.encode(), ctypes.byref(conversation), ctypes.byref(handle))
    if start != 0:
        return False
    try:
        if libpam.pam_authenticate(handle, 0) != 0:
            return False
        if libpam.pam_acct_mgmt(handle, 0) != 0:
            return False
        return True
    finally:
        libpam.pam_end(handle, 0)


def authenticate_local(username: str, password: str) -> bool:
    user = (username or "").strip()
    if not user or password is None or password == "":
        return False
    if any(ch in user for ch in ":\n\r/\\") or len(user) > 64:
        return False
    if not user_may_web_login(user):
        time.sleep(0.15)
        return False
    ok = pam_authenticate(user, password)
    if not ok:
        time.sleep(0.15)
    return ok


def session_secret() -> bytes:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path = CONFIG_DIR / "session.key"
    if path.is_file():
        data = path.read_bytes()
        if len(data) >= 16:
            return data
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def issue_session(username: str) -> str:
    exp = int(time.time()) + SESSION_TTL_SEC
    payload = f"{username}:{exp}"
    sig = hmac.new(session_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode("utf-8")).decode("ascii")


def parse_session(token: str | None) -> str | None:
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        user, exp_s, sig = raw.rsplit(":", 2)
        exp = int(exp_s)
    except (ValueError, OSError):
        return None
    if exp < int(time.time()):
        return None
    payload = f"{user}:{exp}"
    expect = hmac.new(session_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None
    if not user_in_healthd_group(user):
        return None
    return user


def basic_header(username: str, password: str) -> str:
    blob = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return "Basic " + blob


def load_hosts_config() -> dict[str, Any]:
    if config_file("hosts.json").is_file():
        try:
            data = json.loads(config_file("hosts.json").read_text(encoding="utf-8"))
            if isinstance(data, dict):
                hosts = []
                for row in data.get("hosts") or []:
                    if not isinstance(row, dict):
                        continue
                    hid = str(row.get("id") or "")
                    if not RE_HOST_ID.match(hid):
                        continue
                    hosts.append({
                        "id": hid,
                        "name": str(row.get("name") or "").strip()[:40],
                        "address": str(row.get("address") or "").strip()[:80],
                        "base": str(row.get("base") or "").strip()[:120],
                        "username": str(row.get("username") or "").strip()[:64],
                        "password": str(row.get("password") or ""),
                    })
                return {
                    "local_name": str(data.get("local_name") or "").strip()[:40],
                    "hosts": hosts,
                }
        except (OSError, json.JSONDecodeError, TypeError):
            pass
    return {"local_name": "", "hosts": []}


def save_hosts_config(data: dict[str, Any]) -> None:
    payload = {
        "local_name": str(data.get("local_name") or "").strip()[:40],
        "hosts": [
            {
                "id": row["id"],
                "name": str(row.get("name") or "").strip()[:40],
                "address": str(row.get("address") or "").strip()[:80],
                "base": str(row.get("base") or "").strip()[:120],
                "username": str(row.get("username") or "").strip()[:64],
                "password": str(row.get("password") or ""),
            }
            for row in (data.get("hosts") or [])
            if RE_HOST_ID.match(str(row.get("id") or ""))
        ],
    }
    write_config_file("hosts.json", json.dumps(payload, ensure_ascii=False, indent=2))


def parse_remote_address(raw: str) -> tuple[str, str]:
    text = (raw or "").strip()
    if not text or any(ch.isspace() for ch in text):
        raise ValueError("Informe ip:porta, por exemplo 192.168.1.20:9999")
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    if parsed.scheme != "http":
        raise ValueError("Use http://ip:porta (sem TLS neste painel).")
    if parsed.username or parsed.password:
        raise ValueError("Endereço não pode ter usuário/senha.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Informe só o host e a porta, sem caminho.")
    host = parsed.hostname
    if not host:
        raise ValueError("Host inválido.")
    host = host.strip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if host != "localhost" and not RE_DNS_NAME.match(host):
            raise ValueError("Nome de host inválido.") from None
    port = parsed.port or DEFAULT_PORT
    if port < 1 or port > 65535:
        raise ValueError("Porta inválida.")
    try:
        ip = ipaddress.ip_address(host)
        display_host = f"[{host}]" if ip.version == 6 else host
    except ValueError:
        display_host = host
    address = f"{display_host}:{port}"
    return address, f"http://{address}"


def local_host_record() -> dict[str, Any]:
    cfg = load_hosts_config()
    hostname = socket.gethostname()
    name = cfg.get("local_name") or hostname or "esta máquina"
    bind_host = str((DashboardHandler.config or {}).get("bind_host") or DEFAULT_HOST)
    bind_port = int((DashboardHandler.config or {}).get("bind_port") or DEFAULT_PORT)
    return {
        "id": "local",
        "name": name,
        "address": "esta máquina",
        "kind": "local",
        "online": True,
        "version": VERSION,
        "error": None,
        "listen": f"{bind_host}:{bind_port}",
        "hostname": hostname,
    }


def _health_snapshot(host_id: str) -> dict[str, Any]:
    with _hosts_lock:
        row = dict(_hosts_health.get(host_id) or {})
    return {
        "online": bool(row.get("online")),
        "version": row.get("version"),
        "error": row.get("error"),
        "checked_at": row.get("checked_at"),
    }


def probe_remote_base(
    base: str,
    timeout: float = REMOTE_HEALTH_TIMEOUT,
    username: str = "",
    password: str = "",
) -> dict[str, Any]:
    status, payload, err = remote_http(
        "GET", base, "/api/health", "", b"", timeout=timeout, username=username, password=password
    )
    if status == 200 and isinstance(payload, dict) and payload.get("ok"):
        return {"online": True, "version": payload.get("version"), "error": None}
    message = err or (payload.get("message") if isinstance(payload, dict) else None) or f"HTTP {status}"
    return {"online": False, "version": None, "error": str(message)[:180]}


def probe_all_remotes(hosts: list[dict[str, Any]]) -> None:
    threads: list[threading.Thread] = []
    results: dict[str, dict[str, Any]] = {}

    def work(row: dict[str, Any]) -> None:
        results[row["id"]] = probe_remote_base(
            row["base"], username=str(row.get("username") or ""), password=str(row.get("password") or "")
        )

    for row in hosts:
        if not row.get("base"):
            continue
        t = threading.Thread(target=work, args=(row,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(REMOTE_HEALTH_TIMEOUT + 0.8)
    now = iso(now_utc())
    with _hosts_lock:
        for hid, info in results.items():
            _hosts_health[hid] = {**info, "checked_at": now}


def list_hosts_payload(probe: bool = False) -> dict[str, Any]:
    cfg = load_hosts_config()
    remotes = []
    for row in cfg.get("hosts") or []:
        if not row.get("base"):
            try:
                address, base = parse_remote_address(row.get("address") or "")
                row["address"], row["base"] = address, base
            except ValueError:
                continue
        remotes.append(row)
    if probe and remotes:
        probe_all_remotes(remotes)
    items = []
    for row in remotes:
        health = _health_snapshot(row["id"])
        items.append({
            "id": row["id"],
            "name": row["name"] or row["address"],
            "address": row["address"],
            "kind": "remote",
            "username": row.get("username") or "",
            "has_auth": bool(row.get("username") and row.get("password")),
            **health,
        })
    return {"ok": True, "local": local_host_record(), "hosts": items}


def add_remote_host(name: str, address: str, username: str, password: str) -> dict[str, Any]:
    label = (name or "").strip()[:40]
    user = (username or "").strip()[:64]
    secret = str(password or "")
    if not label:
        return {"error": "missing_name", "message": "Dê um nome a este host."}
    if not user or not secret:
        return {"error": "missing_auth", "message": "Informe usuário e senha Linux daquela máquina (grupo healthd)."}
    try:
        display, base = parse_remote_address(address)
    except ValueError as exc:
        return {"error": "invalid_address", "message": str(exc)}
    cfg = load_hosts_config()
    for row in cfg["hosts"]:
        if row.get("base") == base or row.get("address") == display:
            return {"error": "duplicate", "message": "Este endereço já está na lista."}
    host_id = hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]
    cfg["hosts"].append({
        "id": host_id,
        "name": label,
        "address": display,
        "base": base,
        "username": user,
        "password": secret,
    })
    save_hosts_config(cfg)
    health = probe_remote_base(base, username=user, password=secret)
    with _hosts_lock:
        _hosts_health[host_id] = {**health, "checked_at": iso(now_utc())}
    if not health.get("online"):
        return {
            "ok": True,
            "warning": health.get("error") or "Host salvo, mas o login remoto falhou.",
            **list_hosts_payload(probe=False),
        }
    return {"ok": True, **list_hosts_payload(probe=False)}


def rename_host(host_id: str, name: str) -> dict[str, Any]:
    label = (name or "").strip()[:40]
    if not label:
        return {"error": "missing_name", "message": "O nome não pode ficar vazio."}
    cfg = load_hosts_config()
    if host_id == "local":
        cfg["local_name"] = label
        save_hosts_config(cfg)
        return {"ok": True, **list_hosts_payload(probe=False)}
    found = False
    for row in cfg["hosts"]:
        if row["id"] == host_id:
            row["name"] = label
            found = True
            break
    if not found:
        return {"error": "not_found", "message": "Host não encontrado."}
    save_hosts_config(cfg)
    return {"ok": True, **list_hosts_payload(probe=False)}


def remove_remote_host(host_id: str) -> dict[str, Any]:
    if host_id == "local":
        return {"error": "local_host", "message": "Esta máquina não pode ser removida."}
    cfg = load_hosts_config()
    before = len(cfg["hosts"])
    cfg["hosts"] = [row for row in cfg["hosts"] if row["id"] != host_id]
    if len(cfg["hosts"]) == before:
        return {"error": "not_found", "message": "Host não encontrado."}
    save_hosts_config(cfg)
    with _hosts_lock:
        _hosts_health.pop(host_id, None)
    return {"ok": True, **list_hosts_payload(probe=False)}


def find_remote(host_id: str) -> dict[str, Any] | None:
    if not RE_HOST_ID.match(host_id or ""):
        return None
    for row in load_hosts_config().get("hosts") or []:
        if row.get("id") == host_id and row.get("base"):
            return row
    return None


def remote_timeout_for(suffix: str) -> float:
    if suffix == "health":
        return REMOTE_HEALTH_TIMEOUT
    if suffix == "live":
        return 4.0
    if suffix.startswith("disk"):
        return 90.0
    if suffix in {"report", "machine", "machine-tips", "tips", "unit-tips", "ai-chat"}:
        return 40.0
    return 20.0


def remote_http(
    method: str,
    base: str,
    path: str,
    query: str,
    body: bytes,
    timeout: float = 20.0,
    username: str = "",
    password: str = "",
) -> tuple[int, dict[str, Any], str | None]:
    url = base.rstrip("/") + path
    if query:
        url += "?" + query
    headers = {
        "User-Agent": f"{APP_NAME}/{VERSION}",
        "Accept": "application/json",
    }
    if username:
        headers["Authorization"] = basic_header(username, password)
    data = body if body else None
    if data:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(data))
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _REMOTE_OPENER.open(req, timeout=timeout) as resp:
            raw = resp.read(REMOTE_MAX_BYTES + 1)
            if len(raw) > REMOTE_MAX_BYTES:
                return 502, {"error": "too_large", "message": "Resposta remota grande demais."}, "too_large"
            text = raw.decode("utf-8", errors="replace")
            if not text:
                return int(getattr(resp, "status", 200) or 200), {}, None
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                return 502, {"error": "invalid_remote", "message": "O host remoto não devolveu JSON."}, "invalid_json"
            if not isinstance(payload, dict):
                return 502, {"error": "invalid_remote", "message": "JSON remoto inesperado."}, "invalid_json"
            return int(getattr(resp, "status", 200) or 200), payload, None
    except urllib.error.HTTPError as exc:
        raw = exc.read(REMOTE_MAX_BYTES)
        text = raw.decode("utf-8", errors="replace") if raw else ""
        try:
            payload = json.loads(text) if text else {}
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        if not payload:
            payload = {"error": "remote_http", "message": f"O host remoto respondeu HTTP {exc.code}."}
        if exc.code == 401:
            payload = {
                "error": "auth",
                "message": "Usuário/senha recusados no host remoto (precisa ser usuário local no grupo healthd).",
            }
        return int(exc.code), payload, payload.get("message") or f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return 502, {"error": "unreachable", "message": f"Não alcançou o host: {reason}"}, str(reason)
    except TimeoutError:
        return 504, {"error": "timeout", "message": "O host remoto demorou demais."}, "timeout"


def guess_provider(api_key: str) -> str:
    if api_key.startswith("gsk_"):
        return "groq"
    if api_key.startswith("AIza"):
        return "gemini"
    if api_key.startswith("sk-or"):
        return "openrouter"
    return "groq"


def resolve_ai(body: dict[str, Any] | None = None) -> tuple[str, str]:
    body = body or {}
    saved = load_ai_config()
    cli = DashboardHandler.config
    provider = str(
        body.get("provider")
        or cli.get("ai_provider")
        or os.environ.get("HEALTHD_AI_PROVIDER")
        or os.environ.get("JOURNALCTL_OBS_AI_PROVIDER")
        or saved.get("provider")
        or ""
    ).strip().lower()
    api_key = str(
        body.get("api_key")
        or cli.get("ai_key")
        or os.environ.get("GROQ_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
        or os.environ.get("OPENROUTER_API_KEY")
        or saved.get("api_key")
        or ""
    ).strip()
    if not provider:
        if os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
            provider = "gemini"
        elif os.environ.get("OPENROUTER_API_KEY"):
            provider = "openrouter"
        else:
            provider = guess_provider(api_key)
    return provider, api_key


def ai_status() -> dict[str, Any]:
    provider, api_key = resolve_ai()
    return {
        "configured": bool(api_key),
        "provider": provider if api_key else None,
        "signup": {
            "groq": "https://console.groq.com/keys",
            "gemini": "https://aistudio.google.com/apikey",
            "openrouter": "https://openrouter.ai/keys",
        },
    }


def http_json(url: str, payload: dict[str, Any] | None, headers: dict[str, str], timeout: int = 50) -> dict[str, Any]:
    merged = {
        "User-Agent": HTTP_UA,
        "Accept": "application/json",
        **headers,
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=merged, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise classify_http_error(exc.code, detail) from exc
    except urllib.error.URLError as exc:
        raise AiError(f"Falha de rede ao falar com a IA: {exc.reason}", retryable=True) from exc


def classify_http_error(status: int, detail: str) -> AiError:
    lowered = detail.lower()
    if "1010" in detail or "cloudflare" in lowered:
        return AiError(
            "A API bloqueou o cliente HTTP (Cloudflare). Atualize o healthD e tente de novo.",
            status=status,
            retryable=True,
        )
    key_bad = status == 401 or "invalid api key" in lowered or "invalid_api_key" in lowered or "incorrect api key" in lowered
    if key_bad:
        return AiError(
            "A chave foi recusada. Abra Configurar IA no painel e cole uma chave Groq válida (console.groq.com/keys).",
            status=status,
            retryable=False,
        )
    retryable = status in {403, 404, 429} or "not found" in lowered or "does not exist" in lowered or "decommission" in lowered
    return AiError(f"A API de IA retornou HTTP {status}: {detail}", status=status, retryable=retryable)


def parse_model_json(text: str) -> dict[str, Any]:
    blob = text.strip()
    if blob.startswith("```"):
        blob = re.sub(r"^```(?:json)?\s*", "", blob)
        blob = re.sub(r"\s*```$", "", blob)
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", blob, re.S)
        if not match:
            return {
                "summary": blob[:800],
                "likely_cause": "",
                "steps": [blob] if blob else [],
                "commands": [],
                "caution": "",
            }
        data = json.loads(match.group(0))
    if not isinstance(data, dict):
        return {"summary": str(data), "likely_cause": "", "steps": [], "commands": [], "caution": ""}
    commands = []
    for item in data.get("commands") or []:
        if isinstance(item, dict):
            commands.append({"cmd": str(item.get("cmd") or ""), "why": str(item.get("why") or "")})
        elif item:
            commands.append({"cmd": str(item), "why": ""})
    steps = [str(s) for s in (data.get("steps") or []) if str(s).strip()]
    return {
        "summary": str(data.get("summary") or "").strip(),
        "likely_cause": str(data.get("likely_cause") or data.get("cause") or "").strip(),
        "steps": steps,
        "commands": [c for c in commands if c["cmd"]],
        "caution": str(data.get("caution") or "").strip(),
        "bottlenecks": data.get("bottlenecks") if isinstance(data.get("bottlenecks"), list) else [],
        "software": data.get("software") if isinstance(data.get("software"), list) else [],
        "hardware": data.get("hardware") if isinstance(data.get("hardware"), list) else [],
    }


def build_tips_prompt(issue: dict[str, Any], report: dict[str, Any] | None) -> tuple[str, str]:
    stats = (report or {}).get("stats") or {}
    samples = issue.get("samples") or []
    sample_lines = []
    for item in samples[:6]:
        sample_lines.append(f"- [{item.get('t')}] {item.get('message')}")
    context = {
        "host": stats.get("hostname") or socket.gethostname(),
        "periodo": (report or {}).get("since_label"),
        "saude": stats.get("health"),
        "titulo": issue.get("title"),
        "mensagem": issue.get("sample"),
        "severidade": issue.get("severity_label") or issue.get("severity"),
        "app": issue.get("app"),
        "unidade": issue.get("unit"),
        "ocorrencias": issue.get("count"),
        "percentual": issue.get("pct"),
        "impacto": issue.get("impact_label"),
        "melhoria_estimada_pct": issue.get("improvement_pct"),
        "tags": issue.get("tags"),
        "boot": issue.get("boot_label"),
        "contexto_na_ultima_ocorrencia": issue.get("context"),
        "primeira_vez": issue.get("first_seen"),
        "ultima_vez": issue.get("last_seen"),
        "amostras": sample_lines,
    }
    system = (
        "Você é um SRE Linux ajudando o dono desta máquina a entender um evento do journalctl. "
        "Responda em português do Brasil, de forma prática e segura. "
        "Só sugira diagnóstico e correção do próprio sistema do usuário. "
        "Não invente exploits, não peça senhas e não sugira desabilitar segurança sem avisar o risco. "
        "Prefira comandos somente leitura primeiro (journalctl, systemctl status, logs). "
        "Marque claramente qualquer passo que reinicie serviço ou altere config. "
        "Responda APENAS um JSON válido com as chaves: "
        "summary, likely_cause, steps (lista curta), "
        "commands (lista de objetos {cmd, why}), caution."
    )
    user = (
        "Analise este problema agrupado do journald e sugira como investigar e resolver:\n"
        + json.dumps(context, ensure_ascii=False, indent=2)
    )
    return system, user


def groq_discover_models(api_key: str) -> list[str]:
    try:
        payload = http_json(
            "https://api.groq.com/openai/v1/models",
            None,
            {"Authorization": f"Bearer {api_key}"},
            timeout=20,
        )
    except AiError:
        return list(GROQ_MODELS)
    skip = ("whisper", "orpheus", "prompt-guard", "safeguard")
    names = []
    for item in payload.get("data") or []:
        mid = str(item.get("id") or "")
        if not mid or any(token in mid for token in skip):
            continue
        names.append(mid)
    prefer = [name for name in GROQ_MODELS if name in names]
    rest = [name for name in names if name not in prefer]
    return prefer + rest or list(GROQ_MODELS)


def groq_complete_messages(
    api_key: str,
    messages: list[dict[str, str]],
    json_mode: bool = False,
) -> tuple[str, str]:
    last_error: Exception | None = None
    models = groq_discover_models(api_key)
    for model in models:
        body: dict[str, Any] = {
            "model": model,
            "temperature": 0.2 if json_mode else 0.3,
            "messages": messages,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        try:
            payload = http_json(
                "https://api.groq.com/openai/v1/chat/completions",
                body,
                {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            text = payload["choices"][0]["message"]["content"]
            return text, f"groq/{model}"
        except AiError as exc:
            last_error = exc
            if not exc.retryable:
                raise
            continue
        except (KeyError, IndexError) as exc:
            last_error = exc
            continue
    raise AiError(str(last_error) if last_error else "Groq não respondeu.")


def groq_complete(api_key: str, system: str, user: str) -> tuple[str, str]:
    return groq_complete_messages(
        api_key,
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        json_mode=True,
    )


def gemini_discover_models(api_key: str) -> list[str]:
    try:
        payload = http_json(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
            None,
            {"Content-Type": "application/json", "x-goog-api-key": api_key},
            timeout=20,
        )
    except AiError:
        return []
    names: list[str] = []
    for item in payload.get("models") or []:
        methods = item.get("supportedGenerationMethods") or []
        if "generateContent" not in methods:
            continue
        name = str(item.get("name") or "").replace("models/", "")
        if not name or "tts" in name or "image" in name or "embedding" in name:
            continue
        names.append(name)
    flash = [n for n in names if "flash" in n.lower()]
    return flash + [n for n in names if n not in flash]


def gemini_complete_messages(
    api_key: str,
    system: str,
    history: list[dict[str, str]],
    json_mode: bool = False,
) -> tuple[str, str]:
    last_error: Exception | None = None
    models = list(dict.fromkeys([*GEMINI_MODELS, *gemini_discover_models(api_key)]))
    contents = []
    for item in history:
        role = "user" if item.get("role") == "user" else "model"
        contents.append({"role": role, "parts": [{"text": str(item.get("content") or "")}]})
    gen: dict[str, Any] = {"temperature": 0.2 if json_mode else 0.3}
    if json_mode:
        gen["responseMimeType"] = "application/json"
    for model in models:
        try:
            payload = http_json(
                f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}",
                {
                    "systemInstruction": {"parts": [{"text": system}]},
                    "contents": contents,
                    "generationConfig": gen,
                },
                {"Content-Type": "application/json", "x-goog-api-key": api_key},
            )
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
            return text, f"gemini/{model}"
        except AiError as exc:
            last_error = exc
            if not exc.retryable:
                raise
            continue
        except (KeyError, IndexError) as exc:
            last_error = exc
            continue
    raise AiError(
        str(last_error) if last_error else "Gemini não respondeu. Troque a chave ou o provedor em Configurar IA."
    )


def gemini_complete(api_key: str, system: str, user: str) -> tuple[str, str]:
    return gemini_complete_messages(api_key, system, [{"role": "user", "content": user}], json_mode=True)


def openrouter_complete_messages(api_key: str, messages: list[dict[str, str]], json_mode: bool = False) -> tuple[str, str]:
    payload = http_json(
        "https://openrouter.ai/api/v1/chat/completions",
        {
            "model": OPENROUTER_MODEL,
            "temperature": 0.2 if json_mode else 0.3,
            "messages": messages,
        },
        {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://127.0.0.1:9999",
            "X-Title": APP_NAME,
        },
    )
    text = payload["choices"][0]["message"]["content"]
    return text, f"openrouter/{OPENROUTER_MODEL}"


def openrouter_complete(api_key: str, system: str, user: str) -> tuple[str, str]:
    return openrouter_complete_messages(
        api_key,
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        json_mode=True,
    )


def complete_ai(provider: str, api_key: str, system: str, user: str) -> tuple[str, str, str]:
    if provider == "gemini":
        text, model = gemini_complete(api_key, system, user)
    elif provider == "openrouter":
        text, model = openrouter_complete(api_key, system, user)
    else:
        text, model = groq_complete(api_key, system, user)
        provider = "groq"
    return text, model, provider


def complete_chat(
    provider: str,
    api_key: str,
    system: str,
    history: list[dict[str, str]],
) -> tuple[str, str, str]:
    if provider == "gemini":
        text, model = gemini_complete_messages(api_key, system, history, json_mode=False)
    elif provider == "openrouter":
        text, model = openrouter_complete_messages(
            api_key,
            [{"role": "system", "content": system}, *history],
            json_mode=False,
        )
    else:
        text, model = groq_complete_messages(
            api_key,
            [{"role": "system", "content": system}, *history],
            json_mode=False,
        )
        provider = "groq"
    return text, model, provider


CHAT_SYSTEM = (
    "Você é um SRE Linux conversando com o dono desta máquina no painel healthD. "
    "Já existe uma análise inicial neste histórico. Continue o debug em português do Brasil. "
    "Faça perguntas objetivas se faltar dado. Peça para colar a saída de um comando quando isso ajudar. "
    "Não peça senhas, chaves nem exploits. Prefira comandos somente leitura. "
    "Marque qualquer passo que reinicie serviço ou altere configuração. "
    "Responda em texto corrido (não JSON), curto e prático."
)


def format_tips_for_chat(tips: dict[str, Any]) -> str:
    lines: list[str] = []
    if tips.get("summary"):
        lines.append(str(tips["summary"]).strip())
    if tips.get("likely_cause"):
        lines.append("Causa provável: " + str(tips["likely_cause"]).strip())
    for index, step in enumerate(tips.get("steps") or [], 1):
        if str(step).strip():
            lines.append(f"{index}. {step}")
    for cmd in tips.get("commands") or []:
        if isinstance(cmd, dict) and cmd.get("cmd"):
            why = f" — {cmd['why']}" if cmd.get("why") else ""
            lines.append(f"$ {cmd['cmd']}{why}")
        elif cmd:
            lines.append(f"$ {cmd}")
    if tips.get("caution"):
        lines.append("Cuidado: " + str(tips["caution"]).strip())
    return "\n".join(lines) or "Análise inicial pronta. Pode perguntar para continuar o debug."


def format_machine_for_chat(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    if payload.get("summary"):
        lines.append(str(payload["summary"]).strip())
    for item in payload.get("software") or []:
        if isinstance(item, dict) and item.get("title"):
            lines.append("Software: " + str(item["title"]))
            if item.get("why"):
                lines.append("  " + str(item["why"]))
    for item in payload.get("hardware") or []:
        if isinstance(item, dict) and item.get("title"):
            lines.append("Hardware: " + str(item["title"]))
            if item.get("why"):
                lines.append("  " + str(item["why"]))
    if payload.get("caution"):
        lines.append("Cuidado: " + str(payload["caution"]).strip())
    return "\n".join(lines) or "Análise da máquina pronta. Pode perguntar para continuar."


def prune_ai_chats(now: float | None = None) -> None:
    stamp = time.time() if now is None else now
    dead = [key for key, row in _ai_chats.items() if float(row.get("expires") or 0) < stamp]
    for key in dead:
        _ai_chats.pop(key, None)
    if len(_ai_chats) <= 48:
        return
    oldest = sorted(_ai_chats.items(), key=lambda item: float(item[1].get("expires") or 0))
    for key, _ in oldest[: len(_ai_chats) - 40]:
        _ai_chats.pop(key, None)


def visible_chat_messages(thread: dict[str, Any]) -> list[dict[str, str]]:
    messages = thread.get("messages") or []
    follow = messages[2:] if len(messages) >= 2 else messages
    out = []
    for item in follow:
        role = item.get("role")
        if role not in {"user", "assistant"}:
            continue
        out.append({"role": role, "content": str(item.get("content") or "")})
    return out


def remember_chat_thread(kind: str, context_user: str, assistant_text: str) -> str:
    now = time.time()
    with _chat_lock:
        prune_ai_chats(now)
        thread_id = secrets.token_hex(8)
        _ai_chats[thread_id] = {
            "id": thread_id,
            "kind": kind,
            "expires": now + CHAT_TTL_SEC,
            "system": CHAT_SYSTEM,
            "messages": [
                {"role": "user", "content": context_user},
                {"role": "assistant", "content": assistant_text},
            ],
        }
        return thread_id


def attach_chat_thread(payload: dict[str, Any], kind: str, context_user: str, assistant_text: str) -> dict[str, Any]:
    old = str(payload.get("thread_id") or "")
    with _chat_lock:
        prune_ai_chats()
        if old and old in _ai_chats:
            payload["thread_id"] = old
            return payload
    payload["thread_id"] = remember_chat_thread(kind, context_user, assistant_text)
    return payload


def continue_ai_chat(body: dict[str, Any]) -> dict[str, Any]:
    provider, api_key = resolve_ai(body)
    if not api_key:
        return {
            "error": "ai_not_configured",
            "message": "Configure uma chave gratuita para continuar a conversa.",
            "status": ai_status(),
        }
    thread_id = str(body.get("thread_id") or "").strip()
    message = str(body.get("message") or "").strip()[:CHAT_MAX_MESSAGE]
    if not thread_id or not re.fullmatch(r"[a-f0-9]{16}", thread_id):
        return {"error": "chat_missing", "message": "Conversa não encontrada. Peça as dicas outra vez."}
    with _chat_lock:
        prune_ai_chats()
        thread = _ai_chats.get(thread_id)
        if not thread:
            return {"error": "chat_expired", "message": "A conversa expirou. Peça as dicas de novo para reabrir o chat."}
        history = list(thread.get("messages") or [])
        followups = [row for row in history[2:] if row.get("role") == "user"]
        if len(followups) >= CHAT_MAX_FOLLOWUPS:
            return {
                "error": "chat_limit",
                "message": "Esta conversa ficou longa. Peça as dicas de novo para começar outra.",
                "thread_id": thread_id,
                "messages": visible_chat_messages(thread),
            }
        if not message:
            return {
                "ok": True,
                "thread_id": thread_id,
                "messages": visible_chat_messages(thread),
            }
        history.append({"role": "user", "content": message})
        seed, rest = history[:2], history[2:]
        if len(rest) > CHAT_MAX_FOLLOWUPS * 2:
            rest = rest[-(CHAT_MAX_FOLLOWUPS * 2) :]
        send = seed + rest
        system = str(thread.get("system") or CHAT_SYSTEM)
    text, model, provider = complete_chat(provider, api_key, system, send)
    reply = str(text or "").strip()
    with _chat_lock:
        live = _ai_chats.get(thread_id)
        if not live:
            return {"error": "chat_expired", "message": "A conversa expirou no meio da resposta."}
        live["messages"] = send + [{"role": "assistant", "content": reply}]
        live["expires"] = time.time() + CHAT_TTL_SEC
        return {
            "ok": True,
            "thread_id": thread_id,
            "reply": reply,
            "model": model,
            "provider": provider,
            "messages": visible_chat_messages(live),
        }


def generate_tips(issue: dict[str, Any], report: dict[str, Any] | None, body: dict[str, Any]) -> dict[str, Any]:
    provider, api_key = resolve_ai(body)
    if not api_key:
        return {
            "error": "ai_not_configured",
            "message": "Configure uma chave gratuita para gerar dicas.",
            "status": ai_status(),
        }
    cache_key = str(issue.get("id") or hashlib.sha1(str(issue.get("title")).encode()).hexdigest()[:16])
    now = time.time()
    system, user = build_tips_prompt(issue, report)
    with _tips_lock:
        cached = _tips_cache.get(cache_key)
        if cached and cached["expires"] > now and not body.get("refresh"):
            payload = dict(cached["payload"])
            return attach_chat_thread(payload, "issue", user, format_tips_for_chat(payload.get("tips") or {}))

    text, model, provider = complete_ai(provider, api_key, system, user)

    tips = parse_model_json(text)
    payload = {
        "ok": True,
        "provider": provider,
        "model": model,
        "issue_id": cache_key,
        "tips": tips,
    }
    payload = attach_chat_thread(payload, "issue", user, format_tips_for_chat(tips))
    with _tips_lock:
        _tips_cache[cache_key] = {"expires": now + TIPS_TTL_SEC, "payload": payload}
    return payload


def build_unit_tips_prompt(unit: str, logs: dict[str, Any]) -> tuple[str, str]:
    status = logs.get("status") or {}
    entries = logs.get("entries") or []
    excerpt = []
    for item in entries[-80:]:
        excerpt.append(f"- [{item.get('t')}] {item.get('severity')} {item.get('message')}")
    context = {
        "host": socket.gethostname(),
        "unidade": unit,
        "descricao": status.get("description"),
        "active": status.get("active"),
        "sub": status.get("sub"),
        "result": status.get("result"),
        "exec_status": status.get("exec_status"),
        "unit_file_state": status.get("unit_file_state"),
        "fragment": status.get("fragment"),
        "essencial_para_o_linux": bool(logs.get("essential")),
        "periodo_dos_logs": logs.get("since_label"),
        "comando": logs.get("command"),
        "log_de_inicializacao": excerpt,
    }
    system = (
        "Você é um SRE Linux analisando um serviço systemd que falhou ao iniciar. "
        "Responda em português do Brasil, de forma prática e segura. "
        "Use o log de inicialização (journalctl -u / -b) para achar a causa. "
        "Proponha correção no próprio sistema do usuário. "
        "Não invente exploits, não peça senhas e não sugira desabilitar segurança sem avisar o risco. "
        "Prefira comandos somente leitura primeiro. "
        "Se o serviço NÃO for essencial para o Linux bootar (rede, dbus, systemd, getty, display manager), "
        "pode mencionar que desabilitar com systemctl disable --now é uma saída, mas NÃO peça para desligar "
        "serviços essenciais. "
        "Responda APENAS um JSON válido com as chaves: "
        "summary, likely_cause, steps (lista curta), "
        "commands (lista de objetos {cmd, why}), caution."
    )
    user = (
        "Este serviço está failed. Analise o log de inicialização e sugira como corrigir:\n"
        + json.dumps(context, ensure_ascii=False, indent=2)
    )
    return system, user


def generate_unit_tips(
    unit: str,
    body: dict[str, Any],
    user_only: bool,
    demo: bool,
) -> dict[str, Any]:
    unit = _safe_unit_name(unit)
    if not unit:
        return {"error": "missing_unit", "message": "Informe uma unidade systemd."}
    provider, api_key = resolve_ai(body)
    if not api_key:
        return {
            "error": "ai_not_configured",
            "message": "Configure uma chave gratuita para gerar dicas.",
            "status": ai_status(),
        }
    logs = collect_unit_logs(unit, "", "boot", 150, user_only, demo)
    if logs.get("error"):
        return logs
    tail = "|".join(str((row.get("message") or "")[:80]) for row in (logs.get("entries") or [])[-8:])
    cache_key = "unit:" + hashlib.sha1(f"{unit}|{logs.get('status', {}).get('result')}|{tail}".encode()).hexdigest()[:20]
    now = time.time()
    system, user = build_unit_tips_prompt(unit, logs)
    with _tips_lock:
        cached = _tips_cache.get(cache_key)
        if cached and cached["expires"] > now and not body.get("refresh"):
            payload = dict(cached["payload"])
            return attach_chat_thread(payload, "unit", user, format_tips_for_chat(payload.get("tips") or {}))
    text, model, provider = complete_ai(provider, api_key, system, user)
    tips = parse_model_json(text)
    payload = {
        "ok": True,
        "provider": provider,
        "model": model,
        "unit": unit,
        "failed": bool(logs.get("failed")),
        "essential": bool(logs.get("essential")),
        "can_disable": bool(logs.get("can_disable")),
        "tips": tips,
    }
    payload = attach_chat_thread(payload, "unit", user, format_tips_for_chat(tips))
    with _tips_lock:
        _tips_cache[cache_key] = {"expires": now + TIPS_TTL_SEC, "payload": payload}
    return payload


def disable_unit(unit: str, user_only: bool, demo: bool) -> dict[str, Any]:
    unit = _safe_unit_name(unit)
    if not unit:
        return {"error": "missing_unit", "message": "Informe uma unidade systemd.", "ok": False}
    info = {} if demo else _systemctl_show(unit, user_only=user_only)
    failed = True
    if not demo:
        failed = str(info.get("ActiveState") or "").lower() == "failed" or str(info.get("SubState") or "").lower() == "failed"
    else:
        failed = any(row.get("unit") == unit and row.get("bucket") == "failed" for row in demo_service_units().get("units") or [])
    if is_essential_unit(unit, info):
        return {
            "ok": False,
            "error": "essential_unit",
            "essential": True,
            "unit": unit,
            "message": "Este serviço é essencial para o Linux. O disable não está disponível.",
        }
    if not can_disable_unit(unit, info, failed=failed):
        return {
            "ok": False,
            "error": "cannot_disable",
            "essential": False,
            "unit": unit,
            "message": "Só é possível desabilitar serviços failed que não sejam estáticos nem essenciais.",
        }
    command = f"systemctl {'--user ' if user_only else ''}disable --now {unit}"
    if demo:
        return {
            "ok": True,
            "demo": True,
            "unit": unit,
            "command": command,
            "message": "No modo demo o serviço não é alterado.",
        }
    cmd = ["systemctl", "--no-ask-password"]
    if user_only:
        cmd.append("--user")
    cmd.extend(["disable", "--now", unit])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=20, check=False)
    except FileNotFoundError:
        return {"ok": False, "error": "systemctl_missing", "message": "systemctl não encontrado.", "unit": unit}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "message": "systemctl demorou demais.", "unit": unit}
    stderr = proc.stderr.decode("utf-8", errors="replace").strip()
    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0 and not user_only:
        pkexec = shutil.which("pkexec")
        if pkexec:
            try:
                proc = subprocess.run(
                    [pkexec, "systemctl", "disable", "--now", unit],
                    capture_output=True,
                    timeout=90,
                    check=False,
                )
                stderr = proc.stderr.decode("utf-8", errors="replace").strip()
                stdout = proc.stdout.decode("utf-8", errors="replace").strip()
                command = f"pkexec systemctl disable --now {unit}"
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": "disable_failed",
            "unit": unit,
            "command": command,
            "message": stderr or stdout or f"systemctl saiu com código {proc.returncode}.",
        }
    with _svc_lock:
        _svc_cache["expires"] = 0.0
        _svc_cache["payload"] = None
    with _units_lock:
        _units_cache["expires"] = 0.0
        _units_cache["payload"] = None
    return {
        "ok": True,
        "unit": unit,
        "command": command,
        "message": stdout or f"{unit} desabilitado e parado.",
    }


CLK_TCK = os.sysconf("SC_CLK_TCK") or 100
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") or 4096
LIVE_MAX_POINTS = 90
LIVE_LONG_POINTS = 360
LIVE_INTERVAL_SEC = 2.0
RE_SKIP_DISK = re.compile(r"^(loop|ram|sr|fd|zram)")
RE_SKIP_IFACE = re.compile(r"^(lo|sit|ip6tnl|dummy|teql)")
RE_SOCKET = re.compile(r"^socket:\[(\d+)\]$")
RE_PID_DIR = re.compile(r"^\d+$")


def _read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def _cpu_times(line: str) -> dict[str, int]:
    parts = line.split()
    nums = [int(x) for x in parts[1:11]] + [0] * 10
    user, nice, system, idle, iowait, irq, softirq, steal = nums[:8]
    total = sum(nums[:8])
    return {
        "user": user + nice,
        "system": system + irq + softirq,
        "idle": idle,
        "iowait": iowait,
        "steal": steal,
        "total": total or 1,
    }


def _snapshot_cpu() -> dict[str, Any]:
    text = _read_file("/proc/stat") or ""
    cores: list[dict[str, int]] = []
    overall = {"user": 0, "system": 0, "idle": 1, "iowait": 0, "steal": 0, "total": 1}
    for line in text.splitlines():
        if line.startswith("cpu ") :
            overall = _cpu_times(line)
        elif line.startswith("cpu") and line[3:4].isdigit():
            cores.append(_cpu_times(line))
    return {"overall": overall, "cores": cores, "ncpu": max(len(cores), os.cpu_count() or 1)}


def _snapshot_mem() -> dict[str, int]:
    info = {"MemTotal": 1, "MemAvailable": 0, "SwapTotal": 0, "SwapFree": 0, "Buffers": 0, "Cached": 0}
    text = _read_file("/proc/meminfo") or ""
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key in info:
            info[key] = int(rest.strip().split()[0]) * 1024
    used = max(0, info["MemTotal"] - info["MemAvailable"])
    swap_used = max(0, info["SwapTotal"] - info["SwapFree"])
    return {
        "total": info["MemTotal"],
        "available": info["MemAvailable"],
        "used": used,
        "swap_total": info["SwapTotal"],
        "swap_used": swap_used,
        "buffers": info["Buffers"],
        "cached": info["Cached"],
    }


def _snapshot_load() -> dict[str, Any]:
    parts = (_read_file("/proc/loadavg") or "0 0 0 0/1 0").split()
    running, _, tasks = (parts[3] if len(parts) > 3 else "0/1").partition("/")
    return {
        "min1": float(parts[0]),
        "min5": float(parts[1]),
        "min15": float(parts[2]),
        "runnable": int(running or 0),
        "tasks": int(tasks or 1),
    }


def _parse_psi(path: str) -> dict[str, float]:
    info = {"some": 0.0, "full": 0.0}
    text = _read_file(path) or ""
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        if kind not in info:
            continue
        for part in rest.split():
            if part.startswith("avg10="):
                try:
                    info[kind] = float(part.split("=", 1)[1])
                except ValueError:
                    pass
    return info


def _snapshot_psi() -> dict[str, float]:
    mem = _parse_psi("/proc/pressure/memory")
    cpu = _parse_psi("/proc/pressure/cpu")
    io_p = _parse_psi("/proc/pressure/io")
    return {
        "memory_some": mem["some"],
        "memory_full": mem["full"],
        "cpu_some": cpu["some"],
        "io_some": io_p["some"],
    }


def _snapshot_net() -> dict[str, dict[str, int]]:
    text = _read_file("/proc/net/dev") or ""
    ifaces: dict[str, dict[str, int]] = {}
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if not name or RE_SKIP_IFACE.match(name):
            continue
        cols = rest.split()
        if len(cols) < 16:
            continue
        ifaces[name] = {
            "rx_bytes": int(cols[0]),
            "rx_packets": int(cols[1]),
            "rx_errs": int(cols[2]),
            "rx_drop": int(cols[3]),
            "tx_bytes": int(cols[8]),
            "tx_packets": int(cols[9]),
            "tx_errs": int(cols[10]),
            "tx_drop": int(cols[11]),
        }
    return ifaces


def _snapshot_disk() -> dict[str, dict[str, int]]:
    text = _read_file("/proc/diskstats") or ""
    disks: dict[str, dict[str, int]] = {}
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 14:
            continue
        name = cols[2]
        if RE_SKIP_DISK.match(name) or name.startswith("loop"):
            continue
        disks[name] = {
            "read_sectors": int(cols[5]),
            "write_sectors": int(cols[9]),
            "reads": int(cols[3]),
            "writes": int(cols[7]),
            "io_ms": int(cols[12]) if len(cols) > 12 else 0,
        }
    return disks


def _parse_proc_stat(text: str) -> dict[str, Any] | None:
    left = text.find("(")
    right = text.rfind(")")
    if left < 0 or right < 0:
        return None
    try:
        pid = int(text[:left].strip())
    except ValueError:
        return None
    comm = text[left + 1 : right]
    rest = text[right + 2 :].split()
    if len(rest) < 22:
        return None
    return {
        "pid": pid,
        "comm": comm,
        "state": rest[0],
        "ppid": int(rest[1]),
        "utime": int(rest[11]),
        "stime": int(rest[12]),
        "threads": int(rest[17]),
        "rss": int(rest[21]) * PAGE_SIZE,
    }


def _proc_io(pid: int) -> tuple[int, int]:
    text = _read_file(f"/proc/{pid}/io")
    if not text:
        return 0, 0
    read_b = write_b = 0
    for line in text.splitlines():
        if line.startswith("read_bytes:"):
            read_b = int(line.split()[1])
        elif line.startswith("write_bytes:"):
            write_b = int(line.split()[1])
    return read_b, write_b


def _proc_cmd(pid: int, comm: str) -> str:
    raw = _read_file(f"/proc/{pid}/cmdline")
    if raw and raw.strip("\x00"):
        return raw.replace("\x00", " ").strip()[:80]
    return comm


def _socket_owners() -> dict[int, int]:
    owners: dict[int, int] = {}
    try:
        pids = [entry.name for entry in os.scandir("/proc") if entry.is_dir() and RE_PID_DIR.match(entry.name)]
    except OSError:
        return owners
    for name in pids:
        fd_dir = f"/proc/{name}/fd"
        try:
            fds = os.scandir(fd_dir)
        except OSError:
            continue
        pid = int(name)
        with fds:
            for fd in fds:
                try:
                    target = os.readlink(fd.path)
                except OSError:
                    continue
                match = RE_SOCKET.match(target)
                if match:
                    owners[int(match.group(1))] = pid
    return owners


def _socket_counts(owners: dict[int, int]) -> dict[int, int]:
    counts: dict[int, int] = defaultdict(int)
    for table in ("tcp", "tcp6", "udp", "udp6"):
        text = _read_file(f"/proc/net/{table}")
        if not text:
            continue
        for line in text.splitlines()[1:]:
            cols = line.split()
            if len(cols) < 10:
                continue
            try:
                inode = int(cols[9])
            except ValueError:
                continue
            if inode and inode in owners:
                counts[owners[inode]] += 1
    return counts


def _snapshot_procs() -> dict[int, dict[str, Any]]:
    procs: dict[int, dict[str, Any]] = {}
    try:
        entries = os.scandir("/proc")
    except OSError:
        return procs
    with entries:
        names = [entry.name for entry in entries if entry.is_dir() and RE_PID_DIR.match(entry.name)]
    for name in names:
        text = _read_file(f"/proc/{name}/stat")
        if not text:
            continue
        parsed = _parse_proc_stat(text)
        if not parsed:
            continue
        read_b, write_b = _proc_io(parsed["pid"])
        parsed["read_bytes"] = read_b
        parsed["write_bytes"] = write_b
        parsed["cmd"] = _proc_cmd(parsed["pid"], parsed["comm"])
        procs[parsed["pid"]] = parsed
    return procs


def _pct(part: float, whole: float) -> float:
    if whole <= 0:
        return 0.0
    return round(100.0 * part / whole, 1)


def _rate(now: int, prev: int, elapsed: float) -> float:
    if elapsed <= 0 or now < prev:
        return 0.0
    return (now - prev) / elapsed


def _top(items: list[dict[str, Any]], key: str, limit: int) -> list[dict[str, Any]]:
    items = [row for row in items if row.get(key, 0) > 0]
    items.sort(key=lambda row: row.get(key, 0), reverse=True)
    return items[:limit]


class LiveMonitor:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.prev: dict[str, Any] | None = None
        self.history: deque[dict[str, Any]] = deque(maxlen=LIVE_MAX_POINTS)
        self.history_long: deque[dict[str, Any]] = deque(maxlen=LIVE_LONG_POINTS)
        self.latest: dict[str, Any] | None = None
        self.running = False
        self.thread: threading.Thread | None = None
        self.ticks = 0

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, name="live-monitor", daemon=True)
        self.thread.start()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            payload = {
                "version": VERSION,
                "interval": LIVE_INTERVAL_SEC,
                "latest": self.latest,
                "history": list(self.history),
            }
        payload["journal"] = journal_pulse()
        return payload

    def nearest(self, ts_iso: str | None) -> dict[str, Any] | None:
        if not ts_iso:
            return None
        try:
            target = datetime.fromisoformat(str(ts_iso).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
        with self.lock:
            points = list(self.history_long) + list(self.history)
        best = None
        best_dt = 10**9
        for point in points:
            try:
                ts = datetime.fromisoformat(str(point.get("t") or "").replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            delta = abs(ts - target)
            if delta < best_dt:
                best_dt = delta
                best = point
        if best is None or best_dt > 300:
            return None
        return {
            "t": best.get("t"),
            "cpu": best.get("cpu"),
            "iowait": best.get("iowait"),
            "mem": best.get("mem"),
            "load1": best.get("load1"),
            "psi_mem": best.get("psi_mem"),
            "psi_io": best.get("psi_io"),
            "dread": best.get("dread"),
            "dwrite": best.get("dwrite"),
            "skew_sec": int(best_dt),
        }

    def _loop(self) -> None:
        while self.running:
            try:
                raw = {
                    "ts": time.time(),
                    "cpu": _snapshot_cpu(),
                    "mem": _snapshot_mem(),
                    "load": _snapshot_load(),
                    "psi": _snapshot_psi(),
                    "net": _snapshot_net(),
                    "disk": _snapshot_disk(),
                    "procs": _snapshot_procs(),
                    "socks": {},
                }
                owners = _socket_owners()
                raw["socks"] = _socket_counts(owners)
                sample = self._diff(raw)
                with self.lock:
                    self.latest = sample
                    if sample:
                        point = {
                            "t": sample["t"],
                            "cpu": sample["cpu"]["busy"],
                            "iowait": sample["cpu"]["iowait"],
                            "load1": sample["load"]["min1"],
                            "load5": sample["load"]["min5"],
                            "mem": sample["mem"]["pct"],
                            "psi_mem": sample["psi"]["memory_some"],
                            "psi_io": sample["psi"]["io_some"],
                            "rx": sample["net"]["rx_bps"],
                            "tx": sample["net"]["tx_bps"],
                            "dread": sample["disk"]["read_bps"],
                            "dwrite": sample["disk"]["write_bps"],
                        }
                        self.history.append(point)
                        self.ticks += 1
                        if self.ticks % 15 == 1:
                            self.history_long.append(point)
                self.prev = raw
            except Exception:
                pass
            time.sleep(LIVE_INTERVAL_SEC)

    def _diff(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        prev = self.prev
        elapsed = max((raw["ts"] - (prev["ts"] if prev else raw["ts"] - LIVE_INTERVAL_SEC)), 0.2)
        cpu_now = raw["cpu"]["overall"]
        ncpu = raw["cpu"]["ncpu"]
        if prev:
            cpu_prev = prev["cpu"]["overall"]
            total_d = max(cpu_now["total"] - cpu_prev["total"], 1)
            idle_d = max(cpu_now["idle"] - cpu_prev["idle"], 0)
            iowait_d = max(cpu_now["iowait"] - cpu_prev["iowait"], 0)
            user_d = max(cpu_now["user"] - cpu_prev["user"], 0)
            sys_d = max(cpu_now["system"] - cpu_prev["system"], 0)
        else:
            total_d, idle_d, iowait_d, user_d, sys_d = 1, 1, 0, 0, 0
        busy = _pct(total_d - idle_d, total_d)
        cores = []
        prev_cores = (prev["cpu"]["cores"] if prev else [])
        for idx, core in enumerate(raw["cpu"]["cores"]):
            old = prev_cores[idx] if idx < len(prev_cores) else None
            if old:
                ct = max(core["total"] - old["total"], 1)
                cores.append(_pct(ct - max(core["idle"] - old["idle"], 0), ct))
            else:
                cores.append(0.0)

        net_rows = []
        rx_bps = tx_bps = 0.0
        for name, now_if in raw["net"].items():
            old_if = (prev["net"] if prev else {}).get(name) or now_if
            row = {
                "name": name,
                "rx_bps": _rate(now_if["rx_bytes"], old_if["rx_bytes"], elapsed),
                "tx_bps": _rate(now_if["tx_bytes"], old_if["tx_bytes"], elapsed),
                "rx_errs": now_if["rx_errs"],
                "tx_errs": now_if["tx_errs"],
                "rx_drop": now_if["rx_drop"],
                "tx_drop": now_if["tx_drop"],
            }
            rx_bps += row["rx_bps"]
            tx_bps += row["tx_bps"]
            net_rows.append(row)
        net_rows.sort(key=lambda r: r["rx_bps"] + r["tx_bps"], reverse=True)
        active_ifaces = [row for row in net_rows if row["rx_bps"] + row["tx_bps"] > 0]

        disk_rows = []
        read_bps = write_bps = 0.0
        for name, now_d in raw["disk"].items():
            old_d = (prev["disk"] if prev else {}).get(name) or now_d
            row = {
                "name": name,
                "read_bps": _rate(now_d["read_sectors"], old_d["read_sectors"], elapsed) * 512,
                "write_bps": _rate(now_d["write_sectors"], old_d["write_sectors"], elapsed) * 512,
                "reads": _rate(now_d["reads"], old_d["reads"], elapsed),
                "writes": _rate(now_d["writes"], old_d["writes"], elapsed),
            }
            read_bps += row["read_bps"]
            write_bps += row["write_bps"]
            if row["read_bps"] + row["write_bps"] > 0:
                disk_rows.append(row)
        disk_rows.sort(key=lambda r: r["read_bps"] + r["write_bps"], reverse=True)

        proc_rows = []
        prev_procs = prev["procs"] if prev else {}
        for pid, proc in raw["procs"].items():
            old = prev_procs.get(pid)
            ticks = proc["utime"] + proc["stime"]
            old_ticks = (old["utime"] + old["stime"]) if old else ticks
            cpu_pct = 100.0 * max(ticks - old_ticks, 0) / (CLK_TCK * elapsed)
            dread = _rate(proc["read_bytes"], old["read_bytes"] if old else proc["read_bytes"], elapsed)
            dwrite = _rate(proc["write_bytes"], old["write_bytes"] if old else proc["write_bytes"], elapsed)
            socks = int(raw["socks"].get(pid, 0))
            state = proc["state"]
            load_score = cpu_pct * 0.12 + (dread + dwrite) / 20_000_000
            if state == "D":
                load_score += 8.0
            elif state == "R":
                load_score += 5.0
            proc_rows.append(
                {
                    "pid": pid,
                    "name": proc["comm"],
                    "cmd": proc["cmd"],
                    "state": state,
                    "cpu": round(cpu_pct, 1),
                    "rss": proc["rss"],
                    "threads": proc["threads"],
                    "disk_read": dread,
                    "disk_write": dwrite,
                    "sockets": socks,
                    "load_score": round(load_score, 2),
                }
            )

        mem = raw["mem"]
        load = raw["load"]
        psi = raw.get("psi") or _snapshot_psi()
        pressure = _pct(load["min1"], max(ncpu, 1))
        return {
            "t": iso(datetime.fromtimestamp(raw["ts"], tz=timezone.utc)),
            "hostname": socket.gethostname(),
            "ncpu": ncpu,
            "cpu": {
                "busy": busy,
                "user": _pct(user_d, total_d),
                "system": _pct(sys_d, total_d),
                "iowait": _pct(iowait_d, total_d),
                "idle": _pct(idle_d, total_d),
                "cores": cores,
            },
            "mem": {
                **{k: mem[k] for k in ("total", "used", "available", "swap_total", "swap_used")},
                "pct": _pct(mem["used"], mem["total"]),
            },
            "load": {**load, "pressure": round(pressure, 1)},
            "psi": psi,
            "net": {
                "rx_bps": rx_bps,
                "tx_bps": tx_bps,
                "ifaces": (active_ifaces or net_rows)[:12],
            },
            "disk": {
                "read_bps": read_bps,
                "write_bps": write_bps,
                "devices": disk_rows[:12],
            },
            "top": {
                "cpu": _top(proc_rows, "cpu", 10),
                "mem": _top(proc_rows, "rss", 10),
                "disk": _top(
                    [{**p, "disk_total": p["disk_read"] + p["disk_write"]} for p in proc_rows],
                    "disk_total",
                    10,
                ),
                "net": _top(proc_rows, "sockets", 10),
                "load": sorted(proc_rows, key=lambda row: row["load_score"], reverse=True)[:5],
            },
        }


SKIP_FS_NAMES = {"proc", "sys", "dev", "run", "snap"}
DISK_KEEP_BY_DEPTH = (16, 14, 10, 8, 6)
DISK_MAX_DEPTH = 5
DISK_SCAN_SEC = 90.0
REAL_FS = {"ext4", "ext3", "ext2", "xfs", "btrfs", "f2fs", "zfs", "ntfs", "exfat", "vfat", "fuseblk"}


def disk_targets() -> list[dict[str, str]]:
    home = str(Path.home())
    rows = [
        {"id": "home", "label": "Pasta pessoal", "path": home},
        {"id": "root", "label": "Sistema (/)", "path": "/"},
    ]
    seen = {home, "/"}
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                src, mount, fstype = parts[0], parts[1].replace("\\040", " "), parts[2]
                if fstype not in REAL_FS or not src.startswith("/dev/"):
                    continue
                if mount in seen or mount in {"/boot/efi", "/boot"}:
                    continue
                if not os.path.isdir(mount):
                    continue
                seen.add(mount)
                rows.append({"id": mount, "label": mount, "path": mount})
    except OSError:
        pass
    return rows


def _safe_dir(raw: str) -> Path | None:
    text = (raw or "").strip()
    if not text or "\x00" in text:
        return None
    try:
        path = Path(text).expanduser().resolve()
    except OSError:
        return None
    if not path.is_dir():
        return None
    parts = path.parts
    if len(parts) > 1 and parts[1] in {"proc", "sys", "dev"}:
        return None
    return path


def _fs_usage(path: str) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return {"total": 0, "used": 0, "free": 0, "pct": 0.0}
    total = usage.total or 1
    return {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
        "pct": round(100.0 * usage.used / total, 1),
    }


def _demo_disk_tree(root: str) -> dict[str, Any]:
    def node(name: str, path: str, size: int, kids: list[dict[str, Any]] | None = None, files: int = 12, dirs: int = 3) -> dict[str, Any]:
        return {
            "name": name,
            "path": path,
            "size": size,
            "files": files,
            "dirs": dirs,
            "kind": "dir",
            "children": kids or [],
        }

    cache = node(".cache", f"{root}/.cache", 18_000_000_000, [
        node("google-chrome", f"{root}/.cache/google-chrome", 9_400_000_000, [
            node("Default", f"{root}/.cache/google-chrome/Default", 6_100_000_000, files=420, dirs=8),
            node("ShaderCache", f"{root}/.cache/google-chrome/ShaderCache", 2_200_000_000, files=80, dirs=2),
        ], 90, 6),
        node("thumbnails", f"{root}/.cache/thumbnails", 3_100_000_000, files=1800, dirs=4),
        node("pip", f"{root}/.cache/pip", 1_800_000_000, files=220, dirs=12),
    ], 40, 18)
    local = node(".local", f"{root}/.local", 14_200_000_000, [
        node("share", f"{root}/.local/share", 11_000_000_000, [
            node("Trash", f"{root}/.local/share/Trash", 4_400_000_000, files=90, dirs=3),
            node("Steam", f"{root}/.local/share/Steam", 3_800_000_000, files=60, dirs=20),
        ], 30, 12),
        node("lib", f"{root}/.local/lib", 2_400_000_000, files=40, dirs=6),
    ], 20, 8)
    tree = node(Path(root).name or root, root, 46_800_000_000, [
        cache, local,
        node("projetos", f"{root}/projetos", 8_600_000_000, [
            node("node_modules", f"{root}/projetos/node_modules", 5_100_000_000, files=9000, dirs=400),
            node("builds", f"{root}/projetos/builds", 2_200_000_000, files=40, dirs=8),
        ], 200, 24),
        node("Downloads", f"{root}/Downloads", 3_400_000_000, files=80, dirs=6),
        {
            "name": "outros",
            "path": f"{root}/outros",
            "size": 2_600_000_000,
            "files": 120,
            "dirs": 18,
            "kind": "other",
            "children": [],
        },
    ], 2400, 86)
    return tree


def _prune_disk_node(node: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    keep = DISK_KEEP_BY_DEPTH[depth] if depth < len(DISK_KEEP_BY_DEPTH) else 5
    children = sorted(node.get("children") or [], key=lambda row: row.get("size", 0), reverse=True)
    files_size = int(node.pop("file_bytes", 0) or 0)
    kept: list[dict[str, Any]] = []
    rest = 0
    rest_dirs = 0
    rest_files = 0
    for idx, child in enumerate(children):
        if idx < keep and depth < DISK_MAX_DEPTH:
            kept.append(_prune_disk_node(child, depth + 1))
        else:
            rest += int(child.get("size") or 0)
            rest_dirs += 1 + int(child.get("dirs") or 0)
            rest_files += int(child.get("files") or 0)
    if files_size > 0:
        kept.append({
            "name": "arquivos",
            "path": node["path"],
            "size": files_size,
            "files": int(node.get("files") or 0),
            "dirs": 0,
            "kind": "files",
            "children": [],
        })
    if rest > 0:
        kept.append({
            "name": "outros",
            "path": node["path"],
            "size": rest,
            "files": rest_files,
            "dirs": rest_dirs,
            "kind": "other",
            "children": [],
        })
    kept.sort(key=lambda row: row.get("size", 0), reverse=True)
    node["children"] = kept
    return node


def _top_disk_dirs(node: dict[str, Any], limit: int = 12) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def walk(item: dict[str, Any], depth: int) -> None:
        if item.get("kind") in {"files", "other"}:
            return
        if depth > 0:
            rows.append({
                "name": item["name"],
                "path": item["path"],
                "size": item["size"],
                "files": item.get("files", 0),
                "dirs": item.get("dirs", 0),
            })
        for child in item.get("children") or []:
            walk(child, depth + 1)

    walk(node, 0)
    rows.sort(key=lambda row: row["size"], reverse=True)
    return rows[:limit]


class DiskUsage:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.token = 0
        self.status = "idle"
        self.root = str(Path.home())
        self.progress: dict[str, Any] = {"dirs": 0, "files": 0, "bytes": 0, "current": ""}
        self.tree: dict[str, Any] | None = None
        self.error: str | None = None
        self.elapsed = 0.0
        self.fs: dict[str, Any] = _fs_usage(self.root)
        self.thread: threading.Thread | None = None

    def snapshot(self, root: str | None = None, refresh: bool = False, demo: bool = False) -> dict[str, Any]:
        target = _safe_dir(root) if root else Path(self.root)
        if target is None:
            target = Path.home()
        path = str(target)
        if demo:
            tree = _prune_disk_node(_demo_disk_tree(path))
            return self._payload(status="ready", root=path, tree=tree, demo=True)
        with self.lock:
            busy = self.status == "scanning"
            should_start = refresh or self.tree is None or path != self.root
            if busy and path == self.root and not refresh:
                should_start = False
        if should_start:
            self.start(path)
        with self.lock:
            return self._payload()

    def start(self, root: str) -> None:
        with self.lock:
            self.token += 1
            token = self.token
            self.status = "scanning"
            self.root = root
            self.tree = None
            self.error = None
            self.elapsed = 0.0
            self.fs = _fs_usage(root)
            self.progress = {"dirs": 0, "files": 0, "bytes": 0, "current": root}
        self.thread = threading.Thread(target=self._run, args=(token, root), name="disk-usage", daemon=True)
        self.thread.start()

    def inspect(self, raw: str) -> dict[str, Any]:
        path = _safe_dir(raw)
        if path is None:
            return {"error": "invalid_path", "message": "Diretório inválido ou inacessível."}
        entries: list[dict[str, Any]] = []
        try:
            with os.scandir(path) as scan:
                for entry in scan:
                    try:
                        if entry.is_symlink():
                            continue
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    is_dir = stat.S_ISDIR(info.st_mode)
                    size = 0 if is_dir else int(info.st_blocks) * 512
                    entries.append({
                        "name": entry.name,
                        "path": str(path / entry.name),
                        "is_dir": is_dir,
                        "size": size,
                        "mtime": int(info.st_mtime),
                    })
        except OSError as exc:
            return {"error": "list_failed", "message": str(exc)}
        dirs = sorted([row for row in entries if row["is_dir"]], key=lambda row: row["name"].lower())
        files = sorted([row for row in entries if not row["is_dir"]], key=lambda row: row["size"], reverse=True)
        return {
            "ok": True,
            "path": str(path),
            "name": path.name or str(path),
            "dirs": dirs[:80],
            "files": files[:40],
            "dir_count": len(dirs),
            "file_count": len(files),
            "file_bytes": sum(row["size"] for row in files),
        }

    def open_path(self, raw: str) -> dict[str, Any]:
        path = _safe_dir(raw)
        if path is None:
            return {"error": "invalid_path", "message": "Não foi possível abrir este diretório."}
        try:
            subprocess.Popen(
                ["xdg-open", str(path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            return {"error": "open_failed", "message": str(exc)}
        return {"ok": True, "path": str(path)}

    def _payload(self, status: str | None = None, root: str | None = None, tree: dict[str, Any] | None = None, demo: bool = False) -> dict[str, Any]:
        tree = tree if tree is not None else self.tree
        root = root or self.root
        status = status or self.status
        return {
            "version": VERSION,
            "status": status,
            "root": root,
            "targets": disk_targets(),
            "fs": self.fs if root == self.root else _fs_usage(root),
            "progress": dict(self.progress),
            "elapsed": round(self.elapsed, 1),
            "error": self.error,
            "tree": tree,
            "top": _top_disk_dirs(tree) if tree else [],
            "demo": demo,
        }

    def _run(self, token: int, root: str) -> None:
        started = time.time()
        seen: set[tuple[int, int]] = set()
        progress = {"dirs": 0, "files": 0, "bytes": 0, "current": root}
        try:
            st = os.stat(root, follow_symlinks=False)
            tree = self._walk(root, Path(root).name or root, st.st_dev, seen, progress, started, token, 0)
        except OSError as exc:
            tree = None
            error = str(exc)
        else:
            error = None
        elapsed = time.time() - started
        with self.lock:
            if token != self.token:
                return
            self.elapsed = elapsed
            self.progress = progress
            self.fs = _fs_usage(root)
            if tree is None:
                self.status = "error"
                self.error = error or "Falha ao medir o disco."
                self.tree = None
            else:
                self.status = "ready"
                self.error = None
                self.tree = _prune_disk_node(tree)

    def _walk(
        self,
        path: str,
        name: str,
        device: int,
        seen: set[tuple[int, int]],
        progress: dict[str, Any],
        started: float,
        token: int,
        depth: int,
    ) -> dict[str, Any] | None:
        if time.time() - started > DISK_SCAN_SEC:
            return {
                "name": name,
                "path": path,
                "size": 0,
                "files": 0,
                "dirs": 0,
                "kind": "dir",
                "file_bytes": 0,
                "children": [],
            }
        with self.lock:
            if token != self.token:
                return None
            if progress["dirs"] % 40 == 0:
                self.progress = dict(progress)
        node = {
            "name": name,
            "path": path,
            "size": 0,
            "files": 0,
            "dirs": 0,
            "kind": "dir",
            "file_bytes": 0,
            "children": [],
        }
        try:
            scan = os.scandir(path)
        except OSError:
            return node
        children: list[dict[str, Any]] = []
        with scan:
            for entry in scan:
                if time.time() - started > DISK_SCAN_SEC:
                    break
                if entry.name in {".", ".."} or entry.name in SKIP_FS_NAMES:
                    continue
                try:
                    if entry.is_symlink():
                        continue
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if info.st_dev != device:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    child = self._walk(entry.path, entry.name, device, seen, progress, started, token, depth + 1)
                    if child is None:
                        continue
                    children.append(child)
                    node["dirs"] += 1 + int(child.get("dirs") or 0)
                    node["files"] += int(child.get("files") or 0)
                    node["size"] += int(child.get("size") or 0)
                    progress["dirs"] += 1
                    progress["current"] = entry.path
                elif stat.S_ISREG(info.st_mode):
                    key = (info.st_dev, info.st_ino)
                    if key in seen:
                        continue
                    seen.add(key)
                    size = int(info.st_blocks) * 512
                    node["file_bytes"] += size
                    node["size"] += size
                    node["files"] += 1
                    progress["files"] += 1
                    progress["bytes"] += size
        node["children"] = children
        return node


DISK = DiskUsage()

LIVE = LiveMonitor()


def _sysfs_first(path: str) -> str:
    text = _read_file(path)
    return (text or "").strip()


def _cpu_inventory() -> dict[str, Any]:
    model = ""
    mhz = 0.0
    cores_seen: set[str] = set()
    flags = ""
    for line in (_read_file("/proc/cpuinfo") or "").splitlines():
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if key == "model name" and not model:
            model = value
        elif key in {"cpu MHz", "CPU MHz"}:
            try:
                mhz = max(mhz, float(value))
            except ValueError:
                pass
        elif key == "processor":
            cores_seen.add(value)
        elif key == "flags" and not flags:
            flags = value
    ncpu = max(len(cores_seen), os.cpu_count() or 1)
    gov = _sysfs_first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
    max_khz = _sysfs_first("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")
    try:
        max_mhz = round(int(max_khz) / 1000.0, 0) if max_khz else 0
    except ValueError:
        max_mhz = 0
    virt = "vmx" in flags or "svm" in flags
    return {
        "model": model or "CPU",
        "ncpu": ncpu,
        "mhz": round(mhz, 0),
        "max_mhz": max_mhz,
        "governor": gov or "desconhecido",
        "virtualization": virt,
    }


def _dmi_inventory() -> dict[str, str]:
    base = Path("/sys/class/dmi/id")
    def one(name: str) -> str:
        try:
            return (base / name).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""
    return {
        "vendor": one("sys_vendor"),
        "product": one("product_name"),
        "version": one("product_version"),
        "board": one("board_name"),
        "bios": one("bios_version"),
    }


def _block_inventory() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        proc = subprocess.run(
            ["lsblk", "-J", "-b", "-d", "-o", "NAME,SIZE,TYPE,ROTA,MODEL,TRAN"],
            capture_output=True,
            timeout=4,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.lstrip().startswith(b"{"):
            data = json.loads(proc.stdout.decode("utf-8", errors="replace"))
            for item in data.get("blockdevices") or []:
                if str(item.get("type") or "") not in {"disk", "nvme"}:
                    continue
                name = str(item.get("name") or "")
                if not name or name.startswith("loop"):
                    continue
                rows.append(
                    {
                        "name": name,
                        "size": int(item.get("size") or 0),
                        "rotational": bool(item.get("rota")),
                        "model": str(item.get("model") or "").strip(),
                        "transport": str(item.get("tran") or ""),
                        "kind": "hdd" if item.get("rota") else "ssd",
                    }
                )
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
        rows = []
    if rows:
        return rows[:12]
    block = Path("/sys/block")
    try:
        entries = list(block.iterdir())
    except OSError:
        return []
    for entry in entries:
        name = entry.name
        if RE_SKIP_DISK.match(name) or name.startswith("loop"):
            continue
        rota = _sysfs_first(str(entry / "queue" / "rotational")) == "1"
        size_s = _sysfs_first(str(entry / "size"))
        try:
            size = int(size_s) * 512
        except ValueError:
            size = 0
        model = _sysfs_first(str(entry / "device" / "model"))
        rows.append(
            {
                "name": name,
                "size": size,
                "rotational": rota,
                "model": model,
                "transport": "",
                "kind": "hdd" if rota else "ssd",
            }
        )
        if len(rows) >= 12:
            break
    return rows


def _mount_inventory() -> list[dict[str, Any]]:
    rows = []
    for target in disk_targets()[:8]:
        usage = _fs_usage(target["path"])
        rows.append({"path": target["path"], "label": target["label"], **usage})
    return rows


def _gpu_inventory() -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    try:
        proc = subprocess.run(["lspci", "-mm"], capture_output=True, timeout=3, check=False)
        text = proc.stdout.decode("utf-8", errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        text = ""
    for line in text.splitlines():
        low = line.lower()
        if "vga" not in low and "3d controller" not in low and "display controller" not in low:
            continue
        found.append({"name": line.strip()[:140], "source": "lspci"})
    if found:
        return found[:4]
    drm = Path("/sys/class/drm")
    try:
        for card in sorted(drm.glob("card[0-9]")):
            driver = _sysfs_first(str(card / "device" / "uevent")).split("DRIVER=")
            name = driver[1].splitlines()[0] if len(driver) > 1 else card.name
            found.append({"name": name, "source": "drm"})
            if len(found) >= 4:
                break
    except OSError:
        pass
    return found


def _battery_inventory() -> dict[str, Any] | None:
    root = Path("/sys/class/power_supply")
    try:
        bats = [p for p in root.iterdir() if p.name.upper().startswith("BAT")]
    except OSError:
        return None
    if not bats:
        return None
    bat = bats[0]
    def num(name: str) -> int:
        try:
            return int(_sysfs_first(str(bat / name)) or 0)
        except ValueError:
            return 0
    full = num("energy_full") or num("charge_full")
    design = num("energy_full_design") or num("charge_full_design")
    health = round(100.0 * full / design, 1) if design else None
    return {
        "name": bat.name,
        "status": _sysfs_first(str(bat / "status")) or "desconhecido",
        "capacity": num("capacity"),
        "cycle_count": num("cycle_count"),
        "health_pct": health,
        "present": True,
    }


def _thermal_inventory() -> list[dict[str, Any]]:
    rows = []
    zone_root = Path("/sys/class/thermal")
    try:
        zones = sorted(zone_root.glob("thermal_zone*"))
    except OSError:
        return []
    for zone in zones[:8]:
        try:
            temp = int(_sysfs_first(str(zone / "temp")) or 0) / 1000.0
        except ValueError:
            continue
        if temp <= 0:
            continue
        rows.append({"name": _sysfs_first(str(zone / "type")) or zone.name, "celsius": round(temp, 1)})
    rows.sort(key=lambda r: r["celsius"], reverse=True)
    return rows[:6]


def _uptime_sec() -> float:
    try:
        return float((_read_file("/proc/uptime") or "0").split()[0])
    except (TypeError, ValueError):
        return 0.0


def _live_usage() -> dict[str, Any]:
    latest = None
    points: list[dict[str, Any]] = []
    if "LIVE" in globals():
        with LIVE.lock:
            latest = LIVE.latest
            points = list(LIVE.history_long) + list(LIVE.history)
    def series(key: str) -> list[float]:
        return [float(p.get(key) or 0) for p in points if p.get(key) is not None]
    def stats(key: str) -> dict[str, float]:
        vals = series(key)
        if not vals:
            return {"avg": 0.0, "max": 0.0, "last": 0.0, "samples": 0}
        return {
            "avg": round(sum(vals) / len(vals), 2),
            "max": round(max(vals), 2),
            "last": round(vals[-1], 2),
            "samples": len(vals),
        }
    mem = (latest or {}).get("mem") or {}
    cpu = (latest or {}).get("cpu") or {}
    load = (latest or {}).get("load") or {}
    psi = (latest or {}).get("psi") or {}
    disk = (latest or {}).get("disk") or {}
    top = (latest or {}).get("top") or {}
    return {
        "samples": len(points),
        "cpu": stats("cpu"),
        "iowait": stats("iowait"),
        "mem": stats("mem"),
        "psi_mem": stats("psi_mem"),
        "psi_io": stats("psi_io"),
        "load1": stats("load1"),
        "now": {
            "cpu": cpu.get("busy"),
            "iowait": cpu.get("iowait"),
            "mem_pct": mem.get("pct"),
            "mem_used": mem.get("used"),
            "mem_total": mem.get("total"),
            "swap_used": mem.get("swap_used"),
            "swap_total": mem.get("swap_total"),
            "load1": load.get("min1"),
            "ncpu": (latest or {}).get("ncpu"),
            "psi": psi,
            "disk_read": disk.get("read_bps"),
            "disk_write": disk.get("write_bps"),
        },
        "top": {
            "cpu": (top.get("cpu") or [])[:5],
            "mem": (top.get("mem") or [])[:5],
            "load": (top.get("load") or [])[:5],
        },
    }


def _journal_context() -> dict[str, Any]:
    with _cache_lock:
        report = _cache.get("payload")
    if not isinstance(report, dict):
        return {}
    stats = report.get("stats") or {}
    issues = report.get("issues") or []
    oom = report.get("oom") or {}
    failed = report.get("failed_units") or []
    return {
        "health": stats.get("health"),
        "errors": stats.get("errors"),
        "errors_15m": stats.get("errors_15m"),
        "oom": stats.get("oom") or oom.get("count") or 0,
        "oom_events": (oom.get("events") or [])[-6:],
        "failed_units": [row.get("unit") for row in failed[:8]],
        "new_this_boot": stats.get("new_this_boot"),
        "top_issues": [
            {"title": row.get("title"), "app": row.get("app"), "count": row.get("count"), "severity": row.get("severity")}
            for row in issues[:6]
        ],
    }


def detect_bottlenecks(hw: dict[str, Any], usage: dict[str, Any], journal: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    now = usage.get("now") or {}
    mem_now = float(now.get("mem_pct") or 0)
    mem_avg = float((usage.get("mem") or {}).get("avg") or 0)
    mem_max = float((usage.get("mem") or {}).get("max") or 0)
    swap_used = int(now.get("swap_used") or 0)
    swap_total = int(now.get("swap_total") or 0)
    ram = int(now.get("mem_total") or (hw.get("memory") or {}).get("total") or 0)
    swappiness = int(hw.get("vm", {}).get("swappiness") or 60)
    oom = int(journal.get("oom") or 0)
    cpu_avg = float((usage.get("cpu") or {}).get("avg") or 0)
    cpu_max = float((usage.get("cpu") or {}).get("max") or 0)
    load_avg = float((usage.get("load1") or {}).get("avg") or 0)
    ncpu = int(now.get("ncpu") or (hw.get("cpu") or {}).get("ncpu") or 1)
    psi_mem = float((usage.get("psi_mem") or {}).get("avg") or 0)
    psi_io = float((usage.get("psi_io") or {}).get("avg") or 0)
    iowait = float((usage.get("iowait") or {}).get("avg") or 0)
    mounts = hw.get("mounts") or []
    disks = hw.get("disks") or []
    battery = hw.get("battery")
    thermals = hw.get("thermals") or []

    if oom or mem_max >= 94 or mem_avg >= 88 or psi_mem >= 8:
        findings.append({
            "id": "mem",
            "area": "memória",
            "state": "bad" if oom or mem_max >= 96 else "warn",
            "title": "Pressão de memória",
            "detail": f"RAM média {mem_avg:.0f}% (pico {mem_max:.0f}%). {oom} OOM no journal." if oom else f"RAM média {mem_avg:.0f}% e pico {mem_max:.0f}%. PSI mem {psi_mem:.1f}.",
        })
    if swap_total == 0 and (mem_avg >= 80 or oom):
        findings.append({
            "id": "swap-none",
            "area": "swap",
            "state": "warn",
            "title": "Sem swap",
            "detail": "Não há swap. Com a RAM alta, o kernel não tem folga e recorre a OOM killer.",
        })
    elif swap_used > 0 and mem_avg >= 75:
        findings.append({
            "id": "swap-use",
            "area": "swap",
            "state": "warn",
            "title": "Swap em uso",
            "detail": f"Swap {round(swap_used / 1_048_576)} MB de {round(swap_total / 1_048_576)} MB. swappiness={swappiness}.",
        })
    elif swap_total > ram * 1.5 and ram and swap_used < ram * 0.02:
        findings.append({
            "id": "swap-large",
            "area": "swap",
            "state": "ok",
            "title": "Swap grande e ocioso",
            "detail": "Há mais swap do que RAM e quase não está sendo usado. Dá para reduzir se quiser liberar disco.",
        })
    if cpu_avg >= 75 or cpu_max >= 95 or load_avg >= ncpu * 1.4:
        findings.append({
            "id": "cpu",
            "area": "cpu",
            "state": "bad" if cpu_avg >= 90 or load_avg >= ncpu * 2 else "warn",
            "title": "CPU saturada",
            "detail": f"CPU média {cpu_avg:.0f}% (pico {cpu_max:.0f}%). Load 1 {load_avg:.2f} em {ncpu} núcleos.",
        })
    if psi_io >= 8 or iowait >= 18:
        kind = "HDD" if any(d.get("rotational") for d in disks) else "disco"
        findings.append({
            "id": "io",
            "area": "armazenamento",
            "state": "bad" if iowait >= 30 or psi_io >= 20 else "warn",
            "title": f"Gargalo de I/O ({kind})",
            "detail": f"I/O wait médio {iowait:.0f}% · PSI I/O {psi_io:.1f}.",
        })
    for mount in mounts:
        if float(mount.get("pct") or 0) >= 88:
            findings.append({
                "id": f"disk-{mount.get('path')}",
                "area": "armazenamento",
                "state": "bad" if mount["pct"] >= 95 else "warn",
                "title": f"Pouco espaço em {mount.get('path')}",
                "detail": f"{mount.get('pct')}% usado.",
            })
    if battery:
        if battery.get("health_pct") is not None and battery["health_pct"] < 70:
            findings.append({
                "id": "bat-wear",
                "area": "bateria",
                "state": "warn",
                "title": "Bateria desgastada",
                "detail": f"Saúde estimada {battery['health_pct']}% · {battery.get('cycle_count') or '?'} ciclos.",
            })
        if battery.get("status") == "Discharging" and int(battery.get("capacity") or 100) <= 15:
            findings.append({
                "id": "bat-low",
                "area": "bateria",
                "state": "bad",
                "title": "Bateria baixa",
                "detail": f"{battery.get('capacity')}% e descarregando.",
            })
    if thermals and thermals[0]["celsius"] >= 85:
        findings.append({
            "id": "therm",
            "area": "térmico",
            "state": "bad" if thermals[0]["celsius"] >= 95 else "warn",
            "title": "Temperatura alta",
            "detail": f"{thermals[0]['name']}: {thermals[0]['celsius']} °C.",
        })
    failed = journal.get("failed_units") or []
    if failed:
        findings.append({
            "id": "units",
            "area": "serviços",
            "state": "bad",
            "title": "Serviços failed",
            "detail": ", ".join(str(x) for x in failed[:4]),
        })
    if not findings:
        findings.append({
            "id": "ok",
            "area": "sistema",
            "state": "ok",
            "title": "Sem gargalo gritante agora",
            "detail": "Uso dentro do esperado neste recorte. A IA ainda pode sugerir afinações.",
        })
    return findings[:10]


def demo_machine_report() -> dict[str, Any]:
    hw = {
        "cpu": {"model": "Demo CPU 8c", "ncpu": 8, "mhz": 2400, "max_mhz": 4200, "governor": "powersave", "virtualization": True},
        "memory": {"total": 8 * 1024**3, "available": 900 * 1024**2, "used": 7.1 * 1024**3, "swap_total": 2 * 1024**3, "swap_used": 700 * 1024**2},
        "vm": {"swappiness": 60},
        "dmi": {"vendor": "Demo", "product": "Notebook", "bios": "1.0"},
        "disks": [{"name": "sda", "size": 256 * 1024**3, "rotational": True, "model": "TOSHIBA HDD", "kind": "hdd", "transport": "sata"}],
        "mounts": [{"path": "/", "label": "/", "total": 250 * 1024**3, "used": 230 * 1024**3, "free": 20 * 1024**3, "pct": 92.0}],
        "gpus": [{"name": "Intel UHD (demo)", "source": "demo"}],
        "battery": {"name": "BAT0", "status": "Discharging", "capacity": 41, "cycle_count": 640, "health_pct": 72.0, "present": True},
        "thermals": [{"name": "x86_pkg_temp", "celsius": 78.0}],
        "uptime_sec": 86400 * 3,
        "kernel": "demo",
        "hostname": "demo",
    }
    usage = {
        "samples": 40,
        "cpu": {"avg": 42.0, "max": 88.0, "last": 51.0, "samples": 40},
        "iowait": {"avg": 21.0, "max": 47.0, "last": 18.0, "samples": 40},
        "mem": {"avg": 89.0, "max": 97.0, "last": 91.0, "samples": 40},
        "psi_mem": {"avg": 12.0, "max": 40.0, "last": 9.0, "samples": 40},
        "psi_io": {"avg": 15.0, "max": 33.0, "last": 11.0, "samples": 40},
        "load1": {"avg": 3.2, "max": 6.1, "last": 2.8, "samples": 40},
        "now": {
            "cpu": 51.0, "iowait": 18.0, "mem_pct": 91.0,
            "mem_used": int(7.1 * 1024**3), "mem_total": 8 * 1024**3,
            "swap_used": 700 * 1024**2, "swap_total": 2 * 1024**3,
            "load1": 2.8, "ncpu": 8, "psi": {"memory_some": 9.0, "io_some": 11.0},
        },
        "top": {"cpu": [], "mem": [], "load": []},
    }
    journal = {"health": 50, "errors_15m": 12, "oom": 13, "oom_events": [], "failed_units": ["docker.service"], "top_issues": []}
    bottlenecks = detect_bottlenecks(hw, usage, journal)
    return {
        "version": VERSION,
        "generated_at": iso(now_utc()),
        "hardware": hw,
        "usage": usage,
        "journal": journal,
        "bottlenecks": bottlenecks,
        "score": 48,
    }


def _machine_score(findings: list[dict[str, Any]]) -> int:
    score = 100
    for row in findings:
        if row.get("id") == "ok" or row.get("state") == "ok":
            continue
        score -= 18 if row.get("state") == "bad" else 8
    return max(12, min(100, score))


def collect_machine_report(demo: bool = False, refresh: bool = False) -> dict[str, Any]:
    if demo:
        return demo_machine_report()
    now = time.time()
    with _machine_lock:
        cached = _machine_cache.get("payload")
        if not refresh and isinstance(cached, dict) and now < float(_machine_cache.get("expires") or 0):
            return cached
    mem = _snapshot_mem()
    swappiness = 60
    try:
        swappiness = int((_read_file("/proc/sys/vm/swappiness") or "60").strip())
    except ValueError:
        pass
    uname = os.uname()
    hw = {
        "cpu": _cpu_inventory(),
        "memory": mem,
        "vm": {"swappiness": swappiness},
        "dmi": _dmi_inventory(),
        "disks": _block_inventory(),
        "mounts": _mount_inventory(),
        "gpus": _gpu_inventory(),
        "battery": _battery_inventory(),
        "thermals": _thermal_inventory(),
        "uptime_sec": _uptime_sec(),
        "kernel": f"{uname.sysname} {uname.release}",
        "hostname": socket.gethostname(),
    }
    usage = _live_usage()
    if not usage["now"].get("mem_total"):
        usage["now"]["mem_total"] = mem["total"]
        usage["now"]["mem_used"] = mem["used"]
        usage["now"]["swap_total"] = mem["swap_total"]
        usage["now"]["swap_used"] = mem["swap_used"]
        usage["now"]["mem_pct"] = round(100.0 * mem["used"] / max(mem["total"], 1), 1)
        usage["now"]["ncpu"] = hw["cpu"]["ncpu"]
    journal = _journal_context()
    bottlenecks = detect_bottlenecks(hw, usage, journal)
    payload = {
        "version": VERSION,
        "generated_at": iso(now_utc()),
        "hardware": hw,
        "usage": usage,
        "journal": journal,
        "bottlenecks": bottlenecks,
        "score": _machine_score(bottlenecks),
    }
    with _machine_lock:
        _machine_cache["expires"] = time.time() + 15
        _machine_cache["payload"] = payload
    return payload


def compact_machine_for_ai(report: dict[str, Any]) -> dict[str, Any]:
    hw = report.get("hardware") or {}
    usage = report.get("usage") or {}
    mem = hw.get("memory") or {}
    cpu = hw.get("cpu") or {}
    dmi = hw.get("dmi") or {}
    return {
        "host": hw.get("hostname"),
        "maquina": f"{dmi.get('vendor', '')} {dmi.get('product', '')}".strip(),
        "kernel": hw.get("kernel"),
        "uptime_horas": round(float(hw.get("uptime_sec") or 0) / 3600.0, 1),
        "cpu": cpu,
        "ram_bytes": mem.get("total"),
        "swap_bytes": mem.get("swap_total"),
        "swap_usado": mem.get("swap_used"),
        "swappiness": (hw.get("vm") or {}).get("swappiness"),
        "discos": hw.get("disks"),
        "montagens": [
            {"path": m.get("path"), "pct": m.get("pct"), "livre": m.get("free")}
            for m in (hw.get("mounts") or [])
        ],
        "gpus": hw.get("gpus"),
        "bateria": hw.get("battery"),
        "temperaturas": hw.get("thermals"),
        "uso": {
            "cpu": usage.get("cpu"),
            "mem": usage.get("mem"),
            "iowait": usage.get("iowait"),
            "psi_mem": usage.get("psi_mem"),
            "psi_io": usage.get("psi_io"),
            "load1": usage.get("load1"),
            "agora": usage.get("now"),
            "top_cpu": [
                {"name": r.get("name"), "cpu": r.get("cpu")}
                for r in ((usage.get("top") or {}).get("cpu") or [])[:4]
            ],
            "top_mem": [
                {"name": r.get("name"), "rss": r.get("rss")}
                for r in ((usage.get("top") or {}).get("mem") or [])[:4]
            ],
        },
        "journal": report.get("journal"),
        "gargalos_detectados": report.get("bottlenecks"),
        "score_local": report.get("score"),
    }


def generate_machine_tips(body: dict[str, Any], demo: bool) -> dict[str, Any]:
    provider, api_key = resolve_ai(body)
    if not api_key:
        return {
            "error": "ai_not_configured",
            "message": "Configure uma chave gratuita para gerar dicas.",
            "status": ai_status(),
        }
    report = collect_machine_report(demo=demo, refresh=bool(body.get("refresh")))
    context = compact_machine_for_ai(report)
    cache_key = "machine:" + hashlib.sha1(
        json.dumps(
            {
                "score": report.get("score"),
                "ids": [b.get("id") for b in report.get("bottlenecks") or []],
                "oom": (report.get("journal") or {}).get("oom"),
                "mem": ((report.get("usage") or {}).get("mem") or {}).get("avg"),
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()[:20]
    now = time.time()
    system = (
        "Você é um SRE Linux e consultor de hardware analisando ESTA máquina do usuário. "
        "Responda em português do Brasil. "
        "Use evidências do inventário, uso (CPU/RAM/PSI/I/O), journal (OOM, serviços failed) e gargalos já detectados. "
        "Separe claramente o que dá para melhorar por SOFTWARE (swap, governor, serviços, logs, limpeza de disco, swappiness) "
        "do que exige HARDWARE (mais RAM, SSD no lugar de HDD, CPU, bateria, GPU). "
        "Não invente componentes que não aparecem no JSON. Não peça senhas nem exploits. "
        "Prefira comandos somente leitura primeiro. "
        "Responda APENAS um JSON válido com as chaves: "
        "summary (string), "
        "bottlenecks (lista de {area, severity, finding}), "
        "software (lista de {title, why, steps, commands:[{cmd,why}]}), "
        "hardware (lista de {title, why, priority}), "
        "caution (string)."
    )
    user = "Analise esta máquina e proponha melhorias de software e, se fizer sentido, de hardware:\n" + json.dumps(
        context, ensure_ascii=False, indent=2
    )
    with _tips_lock:
        cached = _tips_cache.get(cache_key)
        if cached and cached["expires"] > now and not body.get("refresh"):
            payload = dict(cached["payload"])
            return attach_chat_thread(payload, "machine", user, format_machine_for_chat(payload))
    text, model, provider = complete_ai(provider, api_key, system, user)
    parsed = parse_model_json(text)
    software = []
    for item in parsed.get("software") or []:
        if isinstance(item, dict):
            cmds = []
            for cmd in item.get("commands") or []:
                if isinstance(cmd, dict):
                    cmds.append({"cmd": str(cmd.get("cmd") or ""), "why": str(cmd.get("why") or "")})
                elif cmd:
                    cmds.append({"cmd": str(cmd), "why": ""})
            software.append({
                "title": str(item.get("title") or "").strip(),
                "why": str(item.get("why") or "").strip(),
                "steps": [str(s) for s in (item.get("steps") or []) if str(s).strip()],
                "commands": [c for c in cmds if c["cmd"]],
            })
        elif item:
            software.append({"title": str(item), "why": "", "steps": [], "commands": []})
    if not software and (parsed.get("steps") or parsed.get("commands")):
        software.append({
            "title": parsed.get("summary") or "Ajustes de software",
            "why": parsed.get("likely_cause") or "",
            "steps": parsed.get("steps") or [],
            "commands": parsed.get("commands") or [],
        })
    hardware = []
    for item in parsed.get("hardware") or []:
        if isinstance(item, dict):
            hardware.append({
                "title": str(item.get("title") or "").strip(),
                "why": str(item.get("why") or item.get("finding") or "").strip(),
                "priority": str(item.get("priority") or "média"),
            })
        elif item:
            hardware.append({"title": str(item), "why": "", "priority": "média"})
    ai_bottlenecks = []
    for item in parsed.get("bottlenecks") or []:
        if isinstance(item, dict):
            ai_bottlenecks.append({
                "area": str(item.get("area") or ""),
                "severity": str(item.get("severity") or ""),
                "finding": str(item.get("finding") or item.get("title") or ""),
            })
    payload = {
        "ok": True,
        "provider": provider,
        "model": model,
        "summary": parsed.get("summary") or "",
        "caution": parsed.get("caution") or "",
        "software": software[:8],
        "hardware": hardware[:6],
        "ai_bottlenecks": ai_bottlenecks[:8],
        "score": report.get("score"),
    }
    payload = attach_chat_thread(payload, "machine", user, format_machine_for_chat(payload))
    with _tips_lock:
        _tips_cache[cache_key] = {"expires": now + TIPS_TTL_SEC, "payload": payload}
    return payload


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/{VERSION}"
    config: dict[str, Any] = {}

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _is_public(self, path: str) -> bool:
        if path in {"/login", "/login.html", "/api/login", "/api/logout", "/api/session"}:
            return True
        if path.startswith("/assets/app.css"):
            return True
        if path == "/favicon.ico":
            return True
        return False

    def _cookie(self, name: str) -> str | None:
        raw = self.headers.get("Cookie") or ""
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def _current_user(self) -> str | None:
        header = self.headers.get("Authorization") or ""
        if header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(header.split(None, 1)[1]).decode("utf-8")
            except (ValueError, OSError, IndexError):
                return None
            user, sep, password = decoded.partition(":")
            if not sep:
                return None
            return user.strip() if authenticate_local(user, password) else None
        return parse_session(self._cookie(SESSION_COOKIE))

    def _redirect(self, location: str, status: int = 302) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _deny(self, parsed_path: str) -> None:
        if parsed_path.startswith("/api/"):
            self._send_json({"error": "auth", "message": "Faça login com um usuário local do grupo healthd."}, 401)
            return
        self._redirect("/login")

    def _gate(self, parsed_path: str) -> bool:
        if self._is_public(parsed_path):
            return True
        if not auth_required():
            return True
        if self._current_user():
            return True
        self._deny(parsed_path)
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if not self._gate(parsed.path):
            return
        if parsed.path in {"/login", "/login.html"}:
            self._send_static("/login.html")
            return
        if parsed.path == "/api/session":
            user = self._current_user() if auth_required() else None
            self._send_json({
                "ok": True,
                "required": auth_required(),
                "user": user,
                "group": AUTH_GROUP,
            })
            return
        remote = RE_REMOTE_API.fullmatch(parsed.path)
        if remote:
            self._proxy_remote("GET", remote.group(1), remote.group(2), parsed.query, b"")
            return
        if parsed.path == "/api/hosts":
            query = parse_qs(parsed.query)
            probe = (query.get("probe") or ["0"])[0] in {"1", "true", "yes"}
            self._send_json(list_hosts_payload(probe=probe))
            return
        if parsed.path == "/api/report":
            self._send_report(parsed)
            return
        if parsed.path == "/api/health":
            self._send_json({"ok": True, "version": VERSION})
            return
        if parsed.path == "/api/ai":
            self._send_json(ai_status())
            return
        if parsed.path == "/api/live":
            self._send_json(LIVE.snapshot())
            return
        if parsed.path == "/api/disk":
            self._send_disk(parsed)
            return
        if parsed.path == "/api/disk/ls":
            self._send_disk_ls(parsed)
            return
        if parsed.path == "/api/units":
            self._send_units()
            return
        if parsed.path == "/api/unit-logs":
            self._send_unit_logs(parsed)
            return
        if parsed.path == "/api/machine":
            self._send_machine(parsed)
            return
        self._send_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        raw = self._read_raw_body()
        if raw is None:
            return
        if parsed.path == "/api/login":
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._send_json({"error": "invalid_json"}, 400)
                return
            if not isinstance(body, dict):
                self._send_json({"error": "invalid_json"}, 400)
                return
            user = str(body.get("username") or "")
            password = str(body.get("password") or "")
            if not auth_required():
                self._send_json({"ok": True, "user": user or None, "required": False})
                return
            if not authenticate_local(user, password):
                self._send_json(
                    {"error": "auth", "message": "Usuário, senha ou grupo healthd inválidos."},
                    401,
                )
                return
            token = issue_session(user.strip())
            cookie = f"{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL_SEC}; HttpOnly; SameSite=Lax"
            self._send_json({"ok": True, "user": user.strip()}, 200, extra_headers=[("Set-Cookie", cookie)])
            return
        if parsed.path == "/api/logout":
            cookie = f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
            self._send_json({"ok": True}, 200, extra_headers=[("Set-Cookie", cookie)])
            return
        if not self._gate(parsed.path):
            return
        remote = RE_REMOTE_API.fullmatch(parsed.path)
        if remote:
            self._proxy_remote("POST", remote.group(1), remote.group(2), parsed.query, raw)
            return
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json({"error": "invalid_json"}, 400)
            return
        if not isinstance(body, dict):
            self._send_json({"error": "invalid_json"}, 400)
            return
        if parsed.path == "/api/hosts":
            payload = add_remote_host(
                str(body.get("name") or ""),
                str(body.get("address") or ""),
                str(body.get("username") or ""),
                str(body.get("password") or ""),
            )
            self._send_json(payload, 400 if payload.get("error") else 200)
            return
        if parsed.path == "/api/hosts/rename":
            payload = rename_host(str(body.get("id") or ""), str(body.get("name") or ""))
            self._send_json(payload, 400 if payload.get("error") else 200)
            return
        if parsed.path == "/api/hosts/remove":
            payload = remove_remote_host(str(body.get("id") or ""))
            status = 400 if payload.get("error") else 200
            if payload.get("error") == "local_host":
                status = 403
            self._send_json(payload, status)
            return
        if parsed.path == "/api/tips":
            self._send_tips(body)
            return
        if parsed.path == "/api/ai-chat":
            self._send_ai_chat(body)
            return
        if parsed.path == "/api/unit-tips":
            self._send_unit_tips(body)
            return
        if parsed.path == "/api/unit-disable":
            self._send_unit_disable(body)
            return
        if parsed.path == "/api/machine-tips":
            self._send_machine_tips(body)
            return
        if parsed.path == "/api/ai":
            self._save_ai(body)
            return
        if parsed.path == "/api/disk/open":
            payload = DISK.open_path(str(body.get("path") or ""))
            status = 400 if payload.get("error") else 200
            self._send_json(payload, status)
            return
        self.send_error(404)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if not self._gate(parsed.path):
            return
        remote = RE_REMOTE_API.fullmatch(parsed.path)
        if remote:
            self._proxy_remote("DELETE", remote.group(1), remote.group(2), parsed.query, b"")
            return
        if parsed.path == "/api/ai":
            clear_ai_config()
            clear_tips_cache()
            self._send_json(ai_status())
            return
        self.send_error(404)

    def _read_raw_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 1_000_000:
            self._send_json({"error": "payload_too_large"}, 413)
            return None
        return self.rfile.read(length) if length else b""

    def _read_json_body(self) -> dict[str, Any] | None:
        raw = self._read_raw_body()
        if raw is None:
            return None
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json({"error": "invalid_json"}, 400)
            return None
        if not isinstance(body, dict):
            self._send_json({"error": "invalid_json"}, 400)
            return None
        return body

    def _proxy_remote(self, method: str, host_id: str, suffix: str, query: str, body: bytes) -> None:
        row = find_remote(host_id)
        if not row:
            self._send_json({"error": "not_found", "message": "Host remoto não cadastrado."}, 404)
            return
        status, payload, err = remote_http(
            method,
            row["base"],
            "/api/" + suffix,
            query,
            body,
            timeout=remote_timeout_for(suffix),
            username=str(row.get("username") or ""),
            password=str(row.get("password") or ""),
        )
        if err and suffix == "health":
            with _hosts_lock:
                _hosts_health[host_id] = {
                    "online": False,
                    "version": None,
                    "error": err,
                    "checked_at": iso(now_utc()),
                }
        elif suffix == "health" and status == 200:
            with _hosts_lock:
                _hosts_health[host_id] = {
                    "online": True,
                    "version": payload.get("version"),
                    "error": None,
                    "checked_at": iso(now_utc()),
                }
        if not isinstance(payload, dict):
            payload = {"error": "invalid_remote", "message": "Resposta remota inválida."}
            status = 502
        if status == 401:
            self._send_json({
                "error": "remote_auth",
                "message": payload.get("message")
                or "Usuário/senha recusados no host remoto (precisa ser usuário local no grupo healthd).",
            }, 502)
            return
        self._send_json(payload, status if 100 <= status <= 599 else 502)

    def _save_ai(self, body: dict[str, Any]) -> None:
        api_key = str(body.get("api_key") or "").strip()
        if not api_key:
            self._send_json({"error": "missing_key", "message": "Cole uma chave de API."}, 400)
            return
        provider = str(body.get("provider") or "").strip().lower()
        detected = guess_provider(api_key)
        if detected in {"groq", "gemini", "openrouter"}:
            if provider not in {"groq", "gemini", "openrouter"} or (
                detected != provider and api_key.startswith(("gsk_", "AIza", "sk-or"))
            ):
                provider = detected
        if provider not in {"groq", "gemini", "openrouter"}:
            provider = detected
        save_ai_config(provider, api_key)
        clear_tips_cache()
        self._send_json(ai_status())

    def _send_ai_chat(self, body: dict[str, Any]) -> None:
        try:
            payload = continue_ai_chat(body)
        except AiError as exc:
            self._send_json({"error": "ai_failed", "message": str(exc)}, 502)
            return
        except Exception as exc:
            self._send_json({"error": "ai_failed", "message": str(exc)}, 502)
            return
        if payload.get("error") == "ai_not_configured":
            self._send_json(payload, 412)
            return
        if payload.get("error"):
            self._send_json(payload, 400)
            return
        self._send_json(payload)

    def _send_tips(self, body: dict[str, Any]) -> None:
        issue = body.get("issue")
        if not isinstance(issue, dict) or not (issue.get("title") or issue.get("sample")):
            self._send_json({"error": "missing_issue"}, 400)
            return
        report = None
        with _cache_lock:
            report = _cache.get("payload")
        try:
            payload = generate_tips(issue, report, body)
        except Exception as exc:
            self._send_json({"error": "ai_failed", "message": str(exc)}, 502)
            return
        status = 412 if payload.get("error") == "ai_not_configured" else 200
        self._send_json(payload, status)

    def _send_unit_tips(self, body: dict[str, Any]) -> None:
        unit = str(body.get("unit") or "")
        try:
            payload = generate_unit_tips(
                unit,
                body,
                user_only=bool(self.config.get("user_only")),
                demo=bool(self.config.get("demo")),
            )
        except Exception as exc:
            self._send_json({"error": "ai_failed", "message": str(exc)}, 502)
            return
        if payload.get("error") == "ai_not_configured":
            self._send_json(payload, 412)
            return
        if payload.get("error"):
            self._send_json(payload, 400)
            return
        self._send_json(payload)

    def _send_unit_disable(self, body: dict[str, Any]) -> None:
        payload = disable_unit(
            str(body.get("unit") or ""),
            user_only=bool(self.config.get("user_only")),
            demo=bool(self.config.get("demo")),
        )
        if payload.get("error") == "essential_unit":
            status = 403
        elif not payload.get("ok"):
            status = 400
        else:
            status = 200
        self._send_json(payload, status)

    def _send_machine(self, parsed) -> None:
        query = parse_qs(parsed.query)
        refresh = (query.get("refresh") or ["0"])[0] in {"1", "true", "yes"}
        payload = collect_machine_report(demo=bool(self.config.get("demo")), refresh=refresh)
        self._send_json(payload)

    def _send_machine_tips(self, body: dict[str, Any]) -> None:
        try:
            payload = generate_machine_tips(body, demo=bool(self.config.get("demo")))
        except Exception as exc:
            self._send_json({"error": "ai_failed", "message": str(exc)}, 502)
            return
        if payload.get("error") == "ai_not_configured":
            self._send_json(payload, 412)
            return
        if payload.get("error"):
            self._send_json(payload, 400)
            return
        self._send_json(payload)

    def _send_report(self, parsed) -> None:
        query = parse_qs(parsed.query)
        since = (query.get("since") or ["24h"])[0]
        demo = self.config.get("demo") or (query.get("demo") or ["0"])[0] in {"1", "true", "yes"}
        payload = get_report(
            since_key=since,
            lines=int(self.config.get("lines", DEFAULT_LINES)),
            user_only=bool(self.config.get("user_only")),
            demo=demo,
        )
        self._send_json(payload)

    def _send_disk(self, parsed) -> None:
        query = parse_qs(parsed.query)
        root = (query.get("root") or [None])[0]
        refresh = (query.get("refresh") or ["0"])[0] in {"1", "true", "yes"}
        demo = bool(self.config.get("demo"))
        self._send_json(DISK.snapshot(root, refresh, demo))

    def _send_disk_ls(self, parsed) -> None:
        query = parse_qs(parsed.query)
        path = (query.get("path") or [""])[0]
        payload = DISK.inspect(path)
        status = 400 if payload.get("error") else 200
        self._send_json(payload, status)

    def _send_units(self) -> None:
        payload = collect_service_units(
            user_only=bool(self.config.get("user_only")),
            demo=bool(self.config.get("demo")),
        )
        self._send_json(payload)

    def _send_unit_logs(self, parsed) -> None:
        query = parse_qs(parsed.query)
        try:
            lines = int((query.get("lines") or ["400"])[0])
        except ValueError:
            lines = 400
        payload = collect_unit_logs(
            unit=(query.get("unit") or [""])[0],
            ident=(query.get("ident") or [""])[0],
            since_key=(query.get("since") or ["24h"])[0],
            lines=lines,
            user_only=bool(self.config.get("user_only")),
            demo=bool(self.config.get("demo")),
        )
        status = 400 if payload.get("error") else 200
        self._send_json(payload, status)

    def _send_static(self, path: str) -> None:
        rel = "index.html" if path in {"/", ""} else path.lstrip("/")
        target = (WEB_ROOT / rel).resolve()
        if WEB_ROOT.resolve() not in target.parents and target != WEB_ROOT.resolve():
            self.send_error(403)
            return
        if not target.is_file():
            self.send_error(404)
            return
        data = target.read_bytes()
        ctype = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".json": "application/json",
            ".ico": "image/x-icon",
        }.get(target.suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: dict[str, Any], status: int = 200, extra_headers: list[tuple[str, str]] | None = None) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for key, value in extra_headers or []:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="healthd",
        description="healthD — painel local de saúde da máquina (journal, systemd, hardware, disco e frota).",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Endereço de bind (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Porta HTTP (padrão: 9999)")
    parser.add_argument("--lines", type=int, default=DEFAULT_LINES, help="Máximo de eventos lidos do journal")
    parser.add_argument("--user", action="store_true", help="Ler apenas o journal do usuário")
    parser.add_argument("--demo", action="store_true", help="Usar dados sintéticos (sem journalctl)")
    parser.add_argument("--ai-provider", choices=("groq", "gemini", "openrouter"), help="Provedor de IA Tips (padrão: groq)")
    parser.add_argument("--ai-key", help="Chave da API de IA (senão usa ~/.config/healthd/ai.json ou env)")
    parser.add_argument("--version", action="store_true", help="Mostrar versão e sair")
    args = parser.parse_args(argv)

    if args.version:
        print(VERSION)
        return 0

    if not WEB_ROOT.is_dir():
        print(f"Pasta web não encontrada: {WEB_ROOT}", file=sys.stderr)
        return 1

    DashboardHandler.config = {
        "lines": args.lines,
        "user_only": args.user,
        "demo": args.demo,
        "ai_provider": args.ai_provider or "",
        "ai_key": args.ai_key or "",
        "bind_host": args.host,
        "bind_port": args.port,
    }
    LIVE.start()
    def warmup() -> None:
        try:
            get_report("24h", args.lines, args.user, args.demo)
        except Exception:
            pass

    threading.Thread(target=warmup, name="report-warmup", daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    url = f"http://{args.host}:{args.port}"
    print(f"{APP_NAME} {VERSION}")
    print(f"Dashboard: {url}")
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        print(f"Auth: obrigatória — usuários locais do grupo '{AUTH_GROUP}'")
        if not Path("/etc/pam.d/healthd").is_file():
            print("Aviso: /etc/pam.d/healthd ausente — rode o install.sh nesta máquina", file=sys.stderr)
        if os.geteuid() != 0:
            print(
                "Aviso: sem root o PAM só autentica o próprio usuário deste processo",
                file=sys.stderr,
            )
    if args.demo:
        print("Modo demo: dados sintéticos")
    status = ai_status()
    if status["configured"]:
        print(f"IA Tips: {status['provider']} (plano gratuito)")
    else:
        print("IA Tips: não configurada — cole uma chave Groq grátis no painel")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrado.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
