"""Probe the deployed server the way a client does before it has a token.

Usage:
    python scripts/probe_deployed.py https://<service>.onrender.com [--timeout 180]

Sends no token and no secret. For each request it prints the status, how long it
took, the content type, the headers that tell Render's edge apart from this app,
and the start of the body. Redirects are shown, not followed. Run it once while
the service is awake, and once after it has slept (15+ minutes without traffic)
to see what a non-browser client meets while Render wakes it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-11-25",
        "capabilities": {},
        "clientInfo": {"name": "probe_deployed", "version": "0"},
    },
}

# What a client does first: POST to the MCP URL (expecting 401), then read the metadata.
REQUESTS = [
    ("POST", "/mcp", INITIALIZE),
    ("GET", "/.well-known/oauth-protected-resource/mcp", None),
    ("GET", "/.well-known/oauth-protected-resource", None),
    ("GET", "/mcp", None),
]

SHOWN_HEADERS = (
    "content-type",
    "www-authenticate",
    "location",
    "retry-after",
    "allow",
    "x-render-routing",
    "x-render-origin-server",
    "rndr-id",
    "server",
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # report the redirect itself instead of following it


def probe(base: str, method: str, path: str, body: dict | None, timeout: float) -> None:
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": "probe_deployed/0 (mcp-flashcards-teams)"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/event-stream"
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    started = time.perf_counter()
    try:
        response = opener.open(request, timeout=timeout)
        status, got, payload = response.status, response.headers, response.read(4096)
    except urllib.error.HTTPError as e:
        status, got = e.code, e.headers
        try:
            payload = e.read(4096)
        except Exception as read_error:  # the body can still time out or be cut off
            payload = f"(body not read: {type(read_error).__name__})".encode()
    except Exception as e:  # timeouts, refused connections, TLS errors
        print(f"{method} {path}: no response after {time.perf_counter() - started:.1f}s: {type(e).__name__}: {e}")
        return
    elapsed = time.perf_counter() - started
    print(f"{method} {path}: {status} in {elapsed:.1f}s")
    for name in SHOWN_HEADERS:
        if got.get(name):
            print(f"    {name}: {got.get(name)}")
    text = " ".join(payload.decode("utf-8", errors="replace").split())
    print(f"    body: {text[:300]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", help="e.g. https://<service>.onrender.com")
    parser.add_argument("--timeout", type=float, default=180.0, help="seconds per request (default 180)")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    print(f"probe of {base} at {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M:%S} UTC")
    for method, path, body in REQUESTS:
        probe(base, method, path, body, args.timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
