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
        "status": "Active",
        "raw": line,
    }


def _int_match(name: str, line: str) -> int:
    match = FLOW_RE[name].search(line)
    return int(match.group(1)) if match else 0


def _extract_match(line: str) -> str:
    priority_match = FLOW_RE["priority"].search(line)
    if not priority_match:
        return line.strip().strip(",")

    match_text = line[priority_match.end() :].strip().strip(",")
    return match_text or "all"
