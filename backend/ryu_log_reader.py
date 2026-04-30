"""Compatibility helpers for reading alert state produced by Ryu.

The primary integration is JSON files. This module exists as a small fallback
surface for future log parsing without forcing the API to know where alerts are
stored.
"""

from state_store import get_alerts


def read_alerts():
    return get_alerts()
