"""Mininet process and command-server health checks."""

import socket
import subprocess


COMMAND_HOST = "127.0.0.1"
COMMAND_PORT = 9001


def command_server_running(timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((COMMAND_HOST, COMMAND_PORT), timeout=timeout):
            return True
    except OSError:
        return False


def process_running(pattern: str) -> bool:
    try:
        result = subprocess.run(
            ["pgrep", "-f", pattern],
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def mininet_running() -> bool:
    return command_server_running() or process_running("mininet/topology.py")


def ryu_running() -> bool:
    return process_running("ryu-manager")
