"""In-memory fallback state for the FastAPI demo backend.

Ryu is the source of truth when its WSGI API is reachable. These helpers keep
the dashboard previewable when Ryu or Mininet is not running, without writing
controller-like state through /tmp files.
"""

import random
import time
from typing import Any, Optional


HOSTS = [
    {"host": "h1", "ip": "10.0.0.1", "role": "normal"},
    {"host": "h2", "ip": "10.0.0.2", "role": "normal"},
    {"host": "h3", "ip": "10.0.0.3", "role": "normal"},
    {"host": "h4", "ip": "10.0.0.4", "role": "normal"},
    {"host": "h5", "ip": "10.0.0.5", "role": "normal"},
]
HOST_IP_BY_NAME = {host["host"]: host["ip"] for host in HOSTS}

_status: dict[str, Any] = {}
_stats: dict[str, Any] = {}
_alerts: list[dict[str, Any]] = []


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def now_clock() -> str:
    return time.strftime("%H:%M:%S")


def now_clock_ms() -> str:
    return f"{time.strftime('%H:%M:%S')}.{int((time.time() % 1) * 1000):03d}"


def default_hosts() -> list[dict[str, Any]]:
    return [
        {
            **host,
            "packet_rate": 0,
            "byte_rate": 0,
            "status": "idle",
            "mitigation": None,
        }
        for host in HOSTS
    ]


def normalize_host_role(host: dict[str, Any]) -> dict[str, Any]:
    status = host.get("status")
    mitigation = host.get("mitigation")
    if status == "blocked" or mitigation == "drop":
        role = "attacker"
    elif status in {"rate_limited", "suspicious"} or mitigation == "rate_limit":
        role = "suspicious"
    elif status in {"under_attack", "protected"}:
        role = "victim"
    else:
        role = "normal"
    return {**host, "role": role}


def get_status() -> dict[str, Any]:
    return {
        "demo_state": _status.get("demo_state", "idle"),
        "ryu_running": bool(_status.get("ryu_running", False)),
        "mininet_running": bool(_status.get("mininet_running", False)),
        "last_updated": _status.get("last_updated", now_iso()),
    }


def update_status(**updates: Any) -> dict[str, Any]:
    _status.update(get_status())
    _status.update(updates)
    _status["last_updated"] = now_iso()
    return get_status()


def get_stats() -> dict[str, Any]:
    hosts = _stats.get("hosts")
    if not isinstance(hosts, list):
        hosts = default_hosts()
    else:
        hosts = [normalize_host_role(host) for host in hosts]
    return {
        "hosts": hosts,
        "history": _stats.get("history", []),
        "last_updated": _stats.get("last_updated", now_iso()),
    }


def get_alerts() -> dict[str, Any]:
    return {"alerts": _alerts[-100:]}


def append_alert(level: str, message: str, **fields: Any) -> dict[str, Any]:
    alert = {"time": now_clock(), "level": level, "message": message, **fields}
    if not _alerts or _alerts[-1].get("message") != message:
        _alerts.append(alert)
        del _alerts[:-100]
    return alert


def write_stats(
    hosts: list[dict[str, Any]],
    point: Optional[dict[str, Any]] = None,
    reset_history: bool = False,
) -> dict[str, Any]:
    history = [] if reset_history else list(_stats.get("history", []))
    if point:
        history = [*history, point][-120:]
    _stats.clear()
    _stats.update(
        {
            "hosts": hosts,
            "history": history,
            "last_updated": now_iso(),
        }
    )
    return get_stats()


def synthetic_normal_state() -> None:
    hosts = default_hosts()
    names = [host["host"] for host in hosts]
    random.shuffle(names)
    flows = []
    packet_rates = [42, 55, 64, 72, 78]
    byte_rates = [62000, 79000, 94000, 106000, 115000]
    rates = {}
    for index, src in enumerate(names):
        dst = names[(index + 1) % len(names)]
        flows.append(f"{src}->{dst}")
        rates[src] = (packet_rates[index], byte_rates[index], "active")
    for host in hosts:
        if host["host"] in rates:
            packet_rate, byte_rate, status = rates[host["host"]]
            host.update(packet_rate=packet_rate, byte_rate=byte_rate, status=status)
    total_packet_rate = sum(rate[0] for rate in rates.values())
    total_byte_rate = sum(rate[1] for rate in rates.values())
    write_stats(
        hosts,
        {
            "time": now_clock_ms(),
            "packet_rate": total_packet_rate,
            "byte_rate": total_byte_rate,
            "victim_throughput": total_byte_rate,
        },
    )
    update_status(demo_state="normal")
    append_alert("info", f"Normal traffic started across {', '.join(flows)}")


def synthetic_single_source_flood_state() -> None:
    hosts = default_hosts()
    attacker, victim = random.sample([host["host"] for host in hosts], 2)
    for host in hosts:
        if host["host"] == attacker:
            host.update(
                packet_rate=45000,
                byte_rate=12000000,
                status="blocked",
                mitigation="drop",
                role="attacker",
            )
        elif host["host"] == victim:
            host.update(packet_rate=0, byte_rate=0, status="protected", role="victim")
    write_stats(
        hosts,
        {
            "time": now_clock_ms(),
            "packet_rate": 45000,
            "byte_rate": 12000000,
            "victim_throughput": 0,
        },
    )
    update_status(demo_state="mitigated")
    append_alert(
        "critical",
        (
            f"High-rate flood detected from {HOST_IP_BY_NAME[attacker]} "
            f"to {HOST_IP_BY_NAME[victim]}. Drop rule installed."
        ),
        alert_type="single_source_flood",
        src_ip=HOST_IP_BY_NAME[attacker],
        dst_ip=HOST_IP_BY_NAME[victim],
        mitigation="drop",
    )


def synthetic_multi_source_flood_state() -> None:
    hosts = default_hosts()
    names = [host["host"] for host in hosts]
    victim = random.choice(names)
    attackers = random.sample([name for name in names if name != victim], 3)
    for host in hosts:
        if host["host"] in attackers:
            host.update(
                packet_rate=650,
                byte_rate=520000,
                status="rate_limited",
                role="suspicious",
                mitigation="rate_limit",
            )
        elif host["host"] == victim:
            host.update(
                packet_rate=1950,
                byte_rate=1560000,
                status="under_attack",
                role="victim",
            )
    write_stats(
        hosts,
        {
            "time": now_clock_ms(),
            "packet_rate": 1950,
            "byte_rate": 1560000,
            "victim_throughput": 1560000,
        },
    )
    update_status(demo_state="rate_limited")
    append_alert(
        "warning",
        f"Multiple sources are targeting {HOST_IP_BY_NAME[victim]}. Rate limiting applied.",
        alert_type="multi_source_flood",
        src_ips=[HOST_IP_BY_NAME[name] for name in attackers],
        dst_ip=HOST_IP_BY_NAME[victim],
        mitigation="rate_limit",
    )


def synthetic_stop_state() -> None:
    write_stats(
        default_hosts(),
        {
            "time": now_clock_ms(),
            "packet_rate": 0,
            "byte_rate": 0,
            "victim_throughput": 0,
        },
    )
    update_status(demo_state="idle")
    append_alert("info", "Traffic stopped")


def reset_state() -> None:
    _alerts.clear()
    write_stats(
        default_hosts(),
        {
            "time": now_clock_ms(),
            "packet_rate": 0,
            "byte_rate": 0,
            "victim_throughput": 0,
        },
        reset_history=True,
    )
    update_status(demo_state="idle")
    append_alert("info", "Demo reset")
