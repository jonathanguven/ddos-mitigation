"""Small HTTP client for the Ryu WSGI API."""

import json
import os
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


RYU_REST_BASE_URL = os.getenv("RYU_REST_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
RYU_TIMEOUT_SECONDS = float(os.getenv("RYU_REST_TIMEOUT_SECONDS", "0.75"))


class RyuUnavailable(RuntimeError):
    pass


def get(path: str) -> dict[str, Any]:
    return _request("GET", path)


def post(path: str) -> dict[str, Any]:
    return _request("POST", path)


def _request(method: str, path: str) -> dict[str, Any]:
    url = f"{RYU_REST_BASE_URL}{path}"
    request = Request(url, method=method, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=RYU_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RyuUnavailable(str(exc)) from exc

    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError as exc:
        raise RyuUnavailable(f"Invalid JSON from Ryu: {exc}") from exc
    if not isinstance(payload, dict):
        raise RyuUnavailable("Ryu returned a non-object JSON payload")
    return payload


def fallback_error(exc: Exception) -> str:
    return f"Ryu WSGI API unavailable: {exc.__class__.__name__}"
