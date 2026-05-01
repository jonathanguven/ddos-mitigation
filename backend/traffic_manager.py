"""Traffic command client for the Mininet topology command server."""

import json
import socket
from typing import Any

import ryu_client
from state_store import (
    append_alert,
    reset_state,
    synthetic_multi_source_flood_state,
    synthetic_normal_state,
    synthetic_single_source_flood_state,
    synthetic_stop_state,
    update_status,
)


COMMAND_HOST = "127.0.0.1"
COMMAND_PORT = 9001
TIMEOUT_SECONDS = 2


def send_mininet_command(action: str) -> dict[str, Any]:
    payload = json.dumps({"action": action}).encode("utf-8")
    with socket.create_connection((COMMAND_HOST, COMMAND_PORT), timeout=TIMEOUT_SECONDS) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        raw = sock.recv(4096).decode("utf-8").strip()
    return json.loads(raw or "{}")


def run_action(action: str) -> dict[str, Any]:
    try:
        response = send_mininet_command(action)
        if not response.get("ok", False):
            return {
                "ok": False,
                "mode": "mininet",
                "action": action,
                "message": response.get("error", "Mininet command failed"),
            }
        _apply_success_state(action, response)
        result = {
            "ok": True,
            "mode": "mininet",
            "action": action,
            "message": response.get("message", "Command completed"),
        }
        for key in (
            "attacker",
            "attackers",
            "attacker_ip",
            "attacker_ips",
            "victim",
            "victim_ip",
            "flows",
            "standby_hosts",
        ):
            if key in response:
                result[key] = response[key]
        return result
    except (OSError, json.JSONDecodeError, TimeoutError) as exc:
        _apply_fallback_state(action)
        return {
            "ok": True,
            "mode": "dashboard-fallback",
            "action": action,
            "message": (
                "Mininet command server is not reachable; updated dashboard "
                f"fallback state instead ({exc.__class__.__name__})."
            ),
        }


def _apply_success_state(action: str, response: dict[str, Any]) -> None:
    if action == "start_normal":
        update_status(demo_state="normal", mininet_running=True)
        append_alert("info", response.get("message", "Normal traffic started"))
    elif action == "start_single_source_flood":
        update_status(demo_state="attack", mininet_running=True)
        append_alert(
            "warning",
            response.get("message", "Single-source flood started"),
            alert_type="single_source_flood",
            src_ip=response.get("attacker_ip"),
            dst_ip=response.get("victim_ip"),
        )
    elif action == "start_multi_source_flood":
        update_status(demo_state="attack", mininet_running=True)
        append_alert(
            "warning",
            response.get("message", "Multi-source flood started"),
            alert_type="multi_source_flood",
            src_ips=response.get("attacker_ips"),
            dst_ip=response.get("victim_ip"),
        )
    elif action == "stop_traffic":
        update_status(demo_state="idle", mininet_running=True)
        append_alert("info", "Traffic stopped")
    elif action == "reset":
        reset_state()
        update_status(mininet_running=True)


def _apply_fallback_state(action: str) -> None:
    if action == "start_normal":
        synthetic_normal_state()
    elif action == "start_single_source_flood":
        synthetic_single_source_flood_state()
    elif action == "start_multi_source_flood":
        synthetic_multi_source_flood_state()
    elif action == "stop_traffic":
        synthetic_stop_state()
    elif action == "reset":
        reset_state()


def start_normal() -> dict[str, Any]:
    return run_action("start_normal")


def start_single_source_flood() -> dict[str, Any]:
    return run_action("start_single_source_flood")


def start_multi_source_flood() -> dict[str, Any]:
    return run_action("start_multi_source_flood")


def stop_traffic() -> dict[str, Any]:
    return run_action("stop_traffic")


def reset_demo() -> dict[str, Any]:
    try:
        mininet_response = send_mininet_command("reset")
        mininet_ok = bool(mininet_response.get("ok", False))
        mininet_result = {
            "ok": mininet_ok,
            "mode": "mininet",
            "action": "reset",
            "message": mininet_response.get(
                "message" if mininet_ok else "error",
                "Mininet reset completed" if mininet_ok else "Mininet reset failed",
            ),
        }
    except (OSError, json.JSONDecodeError, TimeoutError) as exc:
        reset_state()
        mininet_result = {
            "ok": True,
            "mode": "dashboard-fallback",
            "action": "reset",
            "message": (
                "Mininet command server is not reachable; reset dashboard "
                f"fallback state instead ({exc.__class__.__name__})."
            ),
        }

    try:
        ryu_response = ryu_client.post("/ryu/reset-controller-state")
        ryu_result = {
            "ok": bool(ryu_response.get("ok", True)),
            "mode": "ryu",
            "action": "reset-controller-state",
            "message": ryu_response.get("message", "Ryu controller state reset"),
        }
    except ryu_client.RyuUnavailable as exc:
        ryu_result = {
            "ok": False,
            "mode": "ryu",
            "action": "reset-controller-state",
            "message": ryu_client.fallback_error(exc),
        }

    if mininet_result["ok"]:
        reset_state()
        update_status(mininet_running=True)

    return {
        "ok": bool(mininet_result["ok"] and ryu_result["ok"]),
        "mode": "combined",
        "action": "reset",
        "message": "Reset sequence completed",
        "mininet": mininet_result,
        "ryu": ryu_result,
    }
