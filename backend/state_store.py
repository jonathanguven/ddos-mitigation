"""Shared state helpers for the FastAPI demo backend.

Ryu is the authoritative producer when it is running. These helpers also keep a
small synthetic fallback state so the React dashboard remains useful before the
Linux SDN stack is started.
"""

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional


STATS_FILE = Path("/tmp/sdn_ids_stats.json")
ALERTS_FILE = Path("/tmp/sdn_ids_alerts.json")
STATE_FILE = Path("/tmp/sdn_ids_state.json")
RESET_FILE = Path("/tmp/sdn_ids_reset.signal")

HOSTS = [
    {"host": "h1", "ip": "10.0.0.1", "role": "attacker"},
    {"host": "h2", "ip": "10.0.0.2", "role": "normal"},
    {"host": "h3", "ip": "10.0.0.3", "role": "normal"},
    {"host": "h4", "ip": "10.0.0.4", "role": "normal"},
    {"host": "h5", "ip": "10.0.0.5", "role": "victim"},
]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def now_clock() -> str:
    return time.strftime("%H:%M:%S")


def default_hosts() -> list[dict[str, Any]]:
    return [
        {
            **host,
            "packet_rate": 0,
            "byte_rate": 0,
            "status": "idle",
        }
        for host in HOSTS
    ]


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return default


def atomic_write(path: Path, payload: Any) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(tmp_path, path)


def get_status() -> dict[str, Any]:
    state = read_json(STATE_FILE, {})
    return {
        "demo_state": state.get("demo_state", "idle"),
        "ryu_running": bool(state.get("ryu_running", False)),
        "mininet_running": bool(state.get("mininet_running", False)),
        "last_updated": state.get("last_updated", now_iso()),
    }


def update_status(**updates: Any) -> dict[str, Any]:
    state = get_status()
    state.update(updates)
    state["last_updated"] = now_iso()
    atomic_write(STATE_FILE, state)
    return state


def get_stats() -> dict[str, Any]:
    stats = read_json(STATS_FILE, {})
    hosts = stats.get("hosts") if isinstance(stats, dict) else None
    if not isinstance(hosts, list):
        hosts = default_hosts()
    return {
        "hosts": hosts,
        "history": stats.get("history", []) if isinstance(stats, dict) else [],
        "last_updated": stats.get("last_updated", now_iso()) if isinstance(stats, dict) else now_iso(),
    }


def get_alerts() -> dict[str, Any]:
    payload = read_json(ALERTS_FILE, {})
    alerts = payload.get("alerts") if isinstance(payload, dict) else payload
    if not isinstance(alerts, list):
        alerts = []
    return {"alerts": alerts[-100:]}


def append_alert(level: str, message: str) -> dict[str, Any]:
    payload = get_alerts()
    alert = {"time": now_clock(), "level": level, "message": message}
    if not payload["alerts"] or payload["alerts"][-1].get("message") != message:
        payload["alerts"].append(alert)
    atomic_write(ALERTS_FILE, {"alerts": payload["alerts"][-100:]})
    return alert


def write_stats(
    hosts: list[dict[str, Any]],
    point: Optional[dict[str, Any]] = None,
    reset_history: bool = False,
) -> dict[str, Any]:
    existing = {} if reset_history else get_stats()
    history = existing.get("history", [])
    if point:
        history = [*history, point][-120:]
    payload = {
        "hosts": hosts,
        "history": history,
        "last_updated": now_iso(),
    }
    atomic_write(STATS_FILE, payload)
    return payload


def synthetic_normal_state() -> None:
    hosts = default_hosts()
    rates = {
        "h2": (18, 1400, "active"),
        "h3": (95, 125000, "active"),
        "h4": (70, 90000, "active"),
        "h5": (183, 216400, "receiving"),
    }
    for host in hosts:
        if host["host"] in rates:
            packet_rate, byte_rate, status = rates[host["host"]]
            host.update(packet_rate=packet_rate, byte_rate=byte_rate, status=status)
    write_stats(
        hosts,
        {
            "time": now_clock(),
            "packet_rate": 183,
            "byte_rate": 216400,
            "victim_throughput": 216400,
        },
    )
    update_status(demo_state="normal")
    append_alert("info", "Normal traffic started")


def synthetic_attack_state() -> None:
    hosts = default_hosts()
    rates = {
        "h1": (45000, 12000000, "suspicious"),
        "h2": (17, 1300, "active"),
        "h3": (88, 110000, "active"),
        "h4": (68, 86000, "active"),
        "h5": (45173, 12197400, "under_attack"),
    }
    for host in hosts:
        if host["host"] in rates:
            packet_rate, byte_rate, status = rates[host["host"]]
            host.update(packet_rate=packet_rate, byte_rate=byte_rate, status=status)
    write_stats(
        hosts,
        {
            "time": now_clock(),
            "packet_rate": 45173,
            "byte_rate": 12197400,
            "victim_throughput": 12197400,
        },
    )
    update_status(demo_state="attack")
    append_alert("warning", "High packet rate detected from h1")
    append_alert("critical", "DDoS suspected against h5")


def synthetic_stop_state() -> None:
    write_stats(
        default_hosts(),
        {
            "time": now_clock(),
            "packet_rate": 0,
            "byte_rate": 0,
            "victim_throughput": 0,
        },
    )
    update_status(demo_state="idle")
    append_alert("info", "Traffic stopped")


def reset_state() -> None:
    try:
        RESET_FILE.write_text(now_iso(), encoding="utf-8")
    except OSError:
        pass
    atomic_write(ALERTS_FILE, {"alerts": []})
    write_stats(
        default_hosts(),
        {
            "time": now_clock(),
            "packet_rate": 0,
            "byte_rate": 0,
            "victim_throughput": 0,
        },
        reset_history=True,
    )
    update_status(demo_state="idle")
    append_alert("info", "Demo reset")
