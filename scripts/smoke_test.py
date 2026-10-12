"""End-to-end smoke test for the demo signing service (standard library only).

Usage:
    python scripts/smoke_test.py [--base-url http://127.0.0.1:8081]

Exits 0 when every check passes, 1 otherwise. Covers: health, sign, verify a
valid token, a tampered token (invalid signature), an expired token, and an
unknown route. Each request is printed so the output can be compared with the
service's request log.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class Result:
    name: str
    ok: bool
    detail: str


def call(
    base: str, method: str, path: str, body: Any = None, raw: bytes | None = None
) -> tuple[int, dict[str, Any]]:
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, text = resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        status, text = exc.code, exc.read().decode("utf-8")
    print(f"  {method:<4} {path:<10} -> {status}")
    try:
        return status, json.loads(text)
    except json.JSONDecodeError:
        return status, {"_raw": text}


def tamper(token: str) -> str:
    """Change one character of the signature segment so the signature no longer matches.

    The token is ``value.timestamp.signature``; the signature is the last segment.
    """
    head, _, sig = token.rpartition(".")
    mid = len(sig) // 2
    flipped = "A" if sig[mid] != "A" else "B"
    return f"{head}.{sig[:mid]}{flipped}{sig[mid + 1:]}"


def run(base: str) -> list[Result]:
    results: list[Result] = []

    def check(name: str, ok: bool, detail: str) -> None:
        results.append(Result(name, ok, detail))
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")

    print("Health")
    status, body = call(base, "GET", "/health")
    check("health", status == 200 and body.get("status") == "ok", f"{status} {body}")

    print("Sign")
    payload = {"user": "alice", "scope": "smoke"}
    status, body = call(base, "POST", "/sign", {"payload": payload})
    token = body.get("token", "")
    check("sign", status == 200 and bool(token), f"{status}, token length {len(token)}")

    print("Verify valid")
    status, body = call(base, "POST", "/verify", {"token": token})
    check(
        "verify valid",
        status == 200 and body.get("payload") == payload and body.get("valid") is True,
        f"{status} payload={body.get('payload')}",
    )

    print("Verify tampered")
    status, body = call(base, "POST", "/verify", {"token": tamper(token)})
    check(
        "verify tampered",
        status == 401 and body.get("error") == "invalid_signature",
        f"{status} error={body.get('error')}",
    )

    print("Verify expired")
    status, body = call(base, "POST", "/sign", {"payload": "short-lived"})
    old_token = body.get("token", "")
    time.sleep(2.1)  # timestamps have 1 s resolution; age must exceed max_age
    status, body = call(base, "POST", "/verify", {"token": old_token, "max_age": 1})
    check(
        "verify expired",
        status == 401 and body.get("error") == "token_expired",
        f"{status} error={body.get('error')}",
    )

    print("Unknown route")
    status, body = call(base, "GET", "/does-not-exist")
    check(
        "unknown route",
        status == 404 and body.get("error") == "not_found",
        f"{status} error={body.get('error')}",
    )

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", default="http://127.0.0.1:8081")
    args = parser.parse_args()

    results = run(args.base_url.rstrip("/"))
    failed = [r for r in results if not r.ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
