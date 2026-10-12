from __future__ import annotations

import json
import logging
import socket
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

from demo_api import ConfigError
from demo_api import DemoServer
from demo_api import make_server
from demo_api import read_secret
from demo_api.app import MAX_BODY_BYTES
from demo_api.app import DemoRequestHandler
from itsdangerous import TimestampSigner
from itsdangerous import URLSafeTimedSerializer

SECRET = "test-secret-key"
SALT = "demo-api"


@pytest.fixture
def server() -> Iterator[DemoServer]:
    srv = make_server(SECRET, host="127.0.0.1", port=0)
    thread = threading.Thread(
        target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


@pytest.fixture
def base(server: DemoServer) -> str:
    host, port = server.server_address[:2]
    return f"http://{host}:{port}"


def request(
    base: str,
    method: str,
    path: str,
    body: Any = None,
    raw: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], Any]:
    data = raw
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(base + path, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status, resp_headers, text = resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        status, resp_headers, text = exc.code, exc.headers, exc.read()
    ctype = resp_headers.get("Content-Type", "")
    if ctype.startswith("application/json"):
        return status, dict(resp_headers), json.loads(text)
    return status, dict(resp_headers), text


def raw_exchange(base: str, data: bytes) -> bytes:
    """Send raw bytes and return the full response (read until the server closes)."""
    host, port = base.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=5) as sock:
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def make_token(payload: Any, salt: str = SALT, secret: str = SECRET) -> str:
    return URLSafeTimedSerializer(secret, salt=salt).dumps(payload)


# ----- configuration ---------------------------------------------------------


def test_read_secret_returns_value() -> None:
    assert read_secret({"DEMO_SECRET": "abc"}) == "abc"


@pytest.mark.parametrize("env", [{}, {"DEMO_SECRET": ""}])
def test_read_secret_requires_non_empty(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError, match="DEMO_SECRET"):
        read_secret(env)


# ----- GET /health and GET / --------------------------------------------------


def test_health(base: str) -> None:
    status, headers, body = request(base, "GET", "/health")
    assert status == 200
    assert body == {"status": "ok", "service": "demo_api"}
    assert headers["Content-Type"].startswith("application/json")


def test_index_page_is_html(base: str) -> None:
    status, headers, body = request(base, "GET", "/")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"Sign text" in body
    assert b"/sign" in body and b"/verify" in body


# ----- POST /sign ------------------------------------------------------------


def test_sign_returns_token_that_verifies_with_library(base: str) -> None:
    status, _, body = request(base, "POST", "/sign", {"payload": {"user": "alice"}})
    assert status == 200
    token = body["token"]
    assert isinstance(token, str) and token
    loaded = URLSafeTimedSerializer(SECRET, salt=SALT).loads(token)
    assert loaded == {"user": "alice"}


@pytest.mark.parametrize("payload", ["text", 42, [1, 2], None, False, {"n": "é"}])
def test_sign_accepts_any_json_payload(base: str, payload: Any) -> None:
    status, _, body = request(base, "POST", "/sign", {"payload": payload})
    assert status == 200
    assert URLSafeTimedSerializer(SECRET, salt=SALT).loads(body["token"]) == payload


def test_sign_custom_salt(base: str) -> None:
    status, _, body = request(base, "POST", "/sign", {"payload": "x", "salt": "other"})
    assert status == 200
    assert URLSafeTimedSerializer(SECRET, salt="other").loads(body["token"]) == "x"
    with pytest.raises(Exception):
        URLSafeTimedSerializer(SECRET, salt=SALT).loads(body["token"])


def test_sign_missing_payload(base: str) -> None:
    status, _, body = request(base, "POST", "/sign", {"salt": "x"})
    assert status == 400
    assert body["error"] == "missing_field"


@pytest.mark.parametrize("salt", ["", 5, None, ["a"]])
def test_sign_invalid_salt(base: str, salt: Any) -> None:
    status, _, body = request(base, "POST", "/sign", {"payload": "x", "salt": salt})
    assert status == 400
    assert body["error"] == "invalid_field"


# ----- POST /verify ----------------------------------------------------------


def test_verify_valid_token_returns_payload(base: str) -> None:
    token = make_token({"user": "bob", "n": 3})
    status, _, body = request(base, "POST", "/verify", {"token": token})
    assert status == 200
    assert body["valid"] is True
    assert body["payload"] == {"user": "bob", "n": 3}
    assert "signed_at" in body


def test_verify_sign_then_verify_roundtrip(base: str) -> None:
    _, _, signed = request(base, "POST", "/sign", {"payload": "hello"})
    status, _, body = request(base, "POST", "/verify", {"token": signed["token"]})
    assert status == 200
    assert body["payload"] == "hello"


def test_verify_tampered_token_is_invalid_signature(base: str) -> None:
    token = make_token("secret-data")
    head, _, sig = token.rpartition(".")
    flipped = "A" if sig[0] != "A" else "B"
    tampered = f"{head}.{flipped}{sig[1:]}"
    status, _, body = request(base, "POST", "/verify", {"token": tampered})
    assert status == 401
    assert body["error"] == "invalid_signature"


def test_verify_tampered_payload_is_invalid_signature(base: str) -> None:
    token = make_token("original")
    value, _, rest = token.partition(".")
    # Swap the value segment for a different encoding while keeping the old signature.
    other = make_token("forged").partition(".")[0]
    status, _, body = request(base, "POST", "/verify", {"token": f"{other}.{rest}"})
    assert status == 401
    assert body["error"] == "invalid_signature"
    assert value != other


def test_verify_wrong_secret_is_invalid_signature(base: str) -> None:
    token = make_token("x", secret="some-other-key")
    status, _, body = request(base, "POST", "/verify", {"token": token})
    assert status == 401
    assert body["error"] == "invalid_signature"


def test_verify_wrong_salt_is_invalid_signature(base: str) -> None:
    token = make_token("x", salt="different")
    status, _, body = request(base, "POST", "/verify", {"token": token})
    assert status == 401
    assert body["error"] == "invalid_signature"


def test_verify_garbage_token_is_invalid_signature(base: str) -> None:
    status, _, body = request(base, "POST", "/verify", {"token": "not-a-token"})
    assert status == 401
    assert body["error"] == "invalid_signature"


def test_verify_signed_but_undecodable_payload_is_malformed(base: str) -> None:
    # A correctly signed value whose body is not valid serializer output.
    token = TimestampSigner(SECRET, salt=SALT).sign("!!!not-base64!!!").decode()
    status, _, body = request(base, "POST", "/verify", {"token": token})
    assert status == 400
    assert body["error"] == "malformed_token"


def test_verify_expired_token(base: str) -> None:
    token = make_token({"a": 1})
    time.sleep(1.1)  # timestamps have one-second resolution
    status, _, body = request(base, "POST", "/verify", {"token": token, "max_age": 0})
    assert status == 401
    assert body["error"] == "token_expired"
    assert "signed_at" in body


def test_verify_within_max_age_is_valid(base: str) -> None:
    token = make_token({"a": 1})
    status, _, body = request(base, "POST", "/verify", {"token": token, "max_age": 3600})
    assert status == 200
    assert body["payload"] == {"a": 1}


def test_verify_expired_error_is_distinct_from_invalid_signature(base: str) -> None:
    token = make_token("x")
    time.sleep(1.1)
    _, _, expired = request(base, "POST", "/verify", {"token": token, "max_age": 0})
    _, _, invalid = request(base, "POST", "/verify", {"token": token[:-2] + "AA"})
    assert expired["error"] != invalid["error"]


@pytest.mark.parametrize(
    "body",
    [{}, {"token": ""}, {"token": 123}, {"token": None}, {"token": ["x"]}],
)
def test_verify_missing_or_invalid_token(base: str, body: dict[str, Any]) -> None:
    status, _, resp = request(base, "POST", "/verify", body)
    assert status == 400
    assert resp["error"] == "missing_field"


@pytest.mark.parametrize("max_age", [-1, "10", True, 1.5, []])
def test_verify_invalid_max_age(base: str, max_age: Any) -> None:
    token = make_token("x")
    status, _, body = request(
        base, "POST", "/verify", {"token": token, "max_age": max_age}
    )
    assert status == 400
    assert body["error"] == "invalid_field"


def test_verify_invalid_salt_field(base: str) -> None:
    status, _, body = request(
        base, "POST", "/verify", {"token": make_token("x"), "salt": ""}
    )
    assert status == 400
    assert body["error"] == "invalid_field"


# ----- request body handling -------------------------------------------------


def test_invalid_json(base: str) -> None:
    status, _, body = request(
        base, "POST", "/sign", raw=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert status == 400
    assert body["error"] == "invalid_json"


@pytest.mark.parametrize("raw", [b"[1, 2]", b'"text"', b"42", b"null", b"NaN"])
def test_body_must_be_json_object(base: str, raw: bytes) -> None:
    status, _, body = request(base, "POST", "/sign", raw=raw)
    assert status == 400
    assert body["error"] == "invalid_json"


def test_empty_body_is_invalid_json(base: str) -> None:
    status, _, body = request(base, "POST", "/sign", raw=b"")
    assert status == 400
    assert body["error"] == "invalid_json"


def test_oversized_body_is_rejected(base: str) -> None:
    raw = b"{" + b" " * (MAX_BODY_BYTES + 1) + b"}"
    status, _, body = request(base, "POST", "/sign", raw=raw)
    assert status == 413
    assert body["error"] == "payload_too_large"


def test_missing_content_length_is_rejected(base: str) -> None:
    data = raw_exchange(base, b"POST /sign HTTP/1.1\r\nHost: x\r\n\r\n")
    assert data.startswith(b"HTTP/1.0 411")
    assert b"length_required" in data


def test_chunked_body_is_rejected(base: str) -> None:
    data = raw_exchange(
        base,
        b"POST /sign HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    assert data.startswith(b"HTTP/1.0 411")
    assert b"length_required" in data


@pytest.mark.parametrize("length", ["abc", "-5"])
def test_bad_content_length(base: str, length: str) -> None:
    data = raw_exchange(
        base,
        f"POST /sign HTTP/1.1\r\nHost: x\r\nContent-Length: {length}\r\n\r\n".encode(),
    )
    assert data.startswith(b"HTTP/1.0 400")


def test_truncated_body_is_rejected(base: str) -> None:
    data = raw_exchange(
        base,
        b'POST /sign HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\n{"payload": 1',
    )
    assert data.startswith(b"HTTP/1.0 400")
    assert b"truncated" in data


# ----- routing ---------------------------------------------------------------


def test_unknown_route_is_404_json(base: str) -> None:
    status, headers, body = request(base, "GET", "/nope")
    assert status == 404
    assert body["error"] == "not_found"
    assert headers["Content-Type"].startswith("application/json")


def test_wrong_method_is_405_with_allow(base: str) -> None:
    status, headers, body = request(base, "GET", "/sign")
    assert status == 405
    assert body["error"] == "method_not_allowed"
    assert headers["Allow"] == "POST"


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
def test_unsupported_methods_on_known_route(base: str, method: str) -> None:
    status, _, body = request(base, method, "/health")
    assert status == 405
    assert body["error"] == "method_not_allowed"


def test_unsupported_method_without_handler_returns_501(base: str) -> None:
    # HEAD has no do_HEAD handler; the stdlib default answers with 501 and no body.
    data = raw_exchange(base, b"HEAD /health HTTP/1.1\r\nHost: x\r\n\r\n")
    assert data.startswith(b"HTTP/1.0 501")


def test_trailing_slash_and_query_string(base: str) -> None:
    status, _, body = request(base, "GET", "/health?x=1")
    assert status == 200
    assert body["status"] == "ok"
    status, _, _ = request(base, "GET", "/health/")
    assert status == 404


def test_unexpected_error_is_500_json(
    base: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: DemoRequestHandler) -> None:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(DemoRequestHandler, "_get_health", boom)
    status, _, body = request(base, "GET", "/health")
    assert status == 500
    assert body == {"error": "internal_error", "message": "Unexpected server error"}
    assert "secret internal detail" not in json.dumps(body)


# ----- request logging -------------------------------------------------------


def test_every_request_is_logged(base: str, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="demo_api")
    request(base, "GET", "/health")
    request(base, "GET", "/missing")
    records = [r.getMessage() for r in caplog.records if r.name == "demo_api"]
    assert any(
        "method=GET" in m and "path='/health'" in m and "status=200" in m
        and "duration_ms=" in m
        for m in records
    )
    assert any(
        "method=GET" in m and "path='/missing'" in m and "status=404" in m
        for m in records
    )


def test_log_path_excludes_query_string(
    base: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="demo_api")
    request(base, "GET", "/health?token=abc")
    messages = [r.getMessage() for r in caplog.records if r.name == "demo_api"]
    assert messages and all("token=abc" not in m for m in messages)
