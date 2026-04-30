"""Open vSwitch flow-table reader and parser."""

import re
import os
import shutil
import subprocess
from typing import Any, Optional


OVS_OFCTL_CANDIDATES = [
    "ovs-ofctl",
    "/usr/bin/ovs-ofctl",
    "/usr/sbin/ovs-ofctl",
    "/sbin/ovs-ofctl",
]

FLOW_RE = {
    "priority": re.compile(r"priority=(\d+)"),
    "packets": re.compile(r"n_packets=(\d+)"),
    "bytes": re.compile(r"n_bytes=(\d+)"),
}
METER_RE = {
    "meter_id": re.compile(r"meter[:=](\d+)"),
    "rate": re.compile(r"rate=(\d+)"),
    "burst_size": re.compile(r"burst_size=(\d+)"),
    "packet_count": re.compile(r"packet(?:_in)?_count[:=](\d+)"),
    "byte_count": re.compile(r"byte(?:_in)?_count[:=](\d+)"),
}


def get_flows(switch: str = "s1") -> dict[str, Any]:
    ovs_ofctl = _find_ovs_ofctl()
    if not ovs_ofctl:
        return {
            "flows": [],
            "raw": [],
            "error": "ovs-ofctl is not installed or is not visible to the backend process",
        }

    command = [ovs_ofctl, "-O", "OpenFlow13", "dump-flows", switch]
    result = _run(command)
    if result.returncode != 0 and shutil.which("sudo"):
        result = _run(["sudo", "-n", *command])

    if result.returncode != 0:
        return {
            "flows": [],
            "raw": [],
            "error": (result.stderr or result.stdout or "Unable to read OVS flows").strip(),
        }

    raw_lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and "NXST_FLOW" not in line
    ]
    return {
        "flows": [parse_flow_line(line, switch) for line in raw_lines],
        "raw": raw_lines,
        "error": None,
    }


def get_meters(switch: str = "s1") -> dict[str, Any]:
    ovs_ofctl = _find_ovs_ofctl()
    if not ovs_ofctl:
        return {
            "meters": [],
            "raw": [],
            "error": "ovs-ofctl is not installed or is not visible to the backend process",
        }

    dump_result = _run_ovs([ovs_ofctl, "-O", "OpenFlow13", "dump-meters", switch])
    stats_result = _run_ovs([ovs_ofctl, "-O", "OpenFlow13", "meter-stats", switch])

    if dump_result.returncode != 0:
        return {
            "meters": [],
            "raw": [],
            "error": (dump_result.stderr or dump_result.stdout or "Unable to read OVS meters").strip(),
        }

    raw_lines = [
        line.strip()
        for line in dump_result.stdout.splitlines()
        if line.strip() and "OFPT_" not in line
    ]
    stats_lines = [
        line.strip()
        for line in stats_result.stdout.splitlines()
        if stats_result.returncode == 0 and line.strip() and "OFPT_" not in line
    ]
    stats_by_meter = {
        parsed["meter_id"]: parsed
        for parsed in (parse_meter_stats_line(line) for line in stats_lines)
        if parsed["meter_id"] is not None
    }
    meters = []
    for line in raw_lines:
        parsed = parse_meter_line(line)
        meter_stats = stats_by_meter.get(parsed["meter_id"], {})
        parsed.update(
            packet_count=meter_stats.get("packet_count", 0),
            byte_count=meter_stats.get("byte_count", 0),
        )
        meters.append(parsed)

    return {
        "meters": meters,
        "raw": raw_lines + stats_lines,
        "error": None if stats_result.returncode == 0 else (stats_result.stderr or "").strip() or None,
    }


def _find_ovs_ofctl() -> Optional[str]:
    for candidate in OVS_OFCTL_CANDIDATES:
        if "/" in candidate:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue

        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(command, 1, "", str(exc))


def _run_ovs(command: list[str]) -> subprocess.CompletedProcess[str]:
    result = _run(command)
    if result.returncode != 0 and shutil.which("sudo"):
        result = _run(["sudo", "-n", *command])
    return result


def parse_flow_line(line: str, switch: str) -> dict[str, Any]:
    actions = ""
    before_actions = line
    if "actions=" in line:
        before_actions, actions = line.rsplit("actions=", 1)

    priority = _int_match("priority", line)
    packets = _int_match("packets", line)
    byte_count = _int_match("bytes", line)
    match = _extract_match(before_actions)

    return {
        "switch": switch,
        "priority": priority,
        "packets": packets,
        "bytes": byte_count,
        "match": match,
        "actions": actions.strip() or "drop",
        "meter_id": _extract_meter_id(actions),
        "status": "Active",
        "raw": line,
    }


def parse_meter_line(line: str) -> dict[str, Any]:
    return {
        "meter_id": _regex_int(METER_RE["meter_id"], line),
        "rate_kbps": _regex_int(METER_RE["rate"], line),
        "burst_size": _regex_int(METER_RE["burst_size"], line),
        "packet_count": 0,
        "byte_count": 0,
        "raw": line,
    }


def parse_meter_stats_line(line: str) -> dict[str, Any]:
    return {
        "meter_id": _regex_int(METER_RE["meter_id"], line),
        "packet_count": _regex_int(METER_RE["packet_count"], line) or 0,
        "byte_count": _regex_int(METER_RE["byte_count"], line) or 0,
        "raw": line,
    }


def _int_match(name: str, line: str) -> int:
    match = FLOW_RE[name].search(line)
    return int(match.group(1)) if match else 0


def _regex_int(pattern: re.Pattern[str], line: str) -> Optional[int]:
    match = pattern.search(line)
    return int(match.group(1)) if match else None


def _extract_meter_id(actions: str) -> Optional[int]:
    for pattern in (r"meter:(\d+)", r"meter=(\d+)"):
        match = re.search(pattern, actions)
        if match:
            return int(match.group(1))
    return None


def _extract_match(line: str) -> str:
    priority_match = FLOW_RE["priority"].search(line)
    if not priority_match:
        return line.strip().strip(",")

    match_text = line[priority_match.end() :].strip().strip(",")
    return match_text or "all"
