"""Internal HTTP service that exposes itsdangerous signing as JSON endpoints.

Standard library only. Tokens are produced by :class:`URLSafeTimedSerializer`
keyed with the ``DEMO_SECRET`` environment variable.
"""

from __future__ import annotations

import json
import logging
import time
import typing as t
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit

from itsdangerous import BadPayload
from itsdangerous import BadSignature
from itsdangerous import SignatureExpired
from itsdangerous import URLSafeTimedSerializer

from .page import INDEX_HTML

logger = logging.getLogger("demo_api")

SECRET_ENV_VAR = "DEMO_SECRET"
DEFAULT_SALT = "demo-api"
MAX_BODY_BYTES = 64 * 1024
REQUEST_TIMEOUT_S = 10.0

_GENERIC_ERROR_CODES = {
    400: "bad_request",
    404: "not_found",
    405: "method_not_allowed",
    411: "length_required",
    413: "payload_too_large",
    500: "internal_error",
    501: "not_implemented",
}


class ConfigError(RuntimeError):
    """Raised when the service is started without a usable secret."""


class ApiError(Exception):
    """An error that is reported to the client as a JSON response."""

    def __init__(
        self,
        status: int,
        error: str,
        message: str,
        details: dict[str, t.Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.error = error
        self.message = message
        self.details = details or {}
        self.headers = headers or {}


def read_secret(environ: t.Mapping[str, str]) -> str:
    """Return the signing key from ``DEMO_SECRET`` or raise :exc:`ConfigError`."""
    secret = environ.get(SECRET_ENV_VAR, "")
    if not secret:
        raise ConfigError(f"{SECRET_ENV_VAR} must be set to a non-empty value")
    return secret


def _optional_salt(body: dict[str, t.Any]) -> str:
    salt = body.get("salt", DEFAULT_SALT)
    if not isinstance(salt, str) or not salt:
        raise ApiError(400, "invalid_field", "'salt' must be a non-empty string")
    return salt


def _reject_constant(name: str) -> t.NoReturn:
    raise ValueError(f"{name} is not allowed in JSON")


class DemoRequestHandler(BaseHTTPRequestHandler):
    server_version = "DemoAPI/1.0"
    protocol_version = "HTTP/1.0"
    timeout = REQUEST_TIMEOUT_S

    # Per-request state, reset in handle_one_request.
    raw_requestline: bytes = b""
    command: str | None = None
    path: str = ""
    _status: int | None = None

    #: Routes keyed by (method, path) to the handler method name.
    ROUTES: t.ClassVar[dict[tuple[str, str], str]] = {
        ("GET", "/"): "_get_index",
        ("GET", "/health"): "_get_health",
        ("POST", "/sign"): "_post_sign",
        ("POST", "/verify"): "_post_verify",
    }

    # ----- request lifecycle -------------------------------------------------

    def handle_one_request(self) -> None:
        self.raw_requestline = b""
        self.command = None
        self.path = ""
        self._status = None
        started = time.perf_counter()
        try:
            super().handle_one_request()
        finally:
            if self.raw_requestline:
                elapsed_ms = (time.perf_counter() - started) * 1000
                logger.info(
                    "method=%s path=%r status=%s duration_ms=%.2f",
                    self.command or "-",
                    urlsplit(self.path).path if self.path else "-",
                    self._status or "-",
                    elapsed_ms,
                )

    def log_message(self, format: str, *args: t.Any) -> None:
        # Request logging is done in handle_one_request; silence the default.
        pass

    def send_response(self, code: int, message: str | None = None) -> None:
        self._status = int(code)
        super().send_response(code, message)

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        status = int(code)
        body = {
            "error": _GENERIC_ERROR_CODES.get(status, "error"),
            "message": message or "Request could not be processed",
        }
        self._send_json(status, body, {"Connection": "close"})

    def _dispatch(self) -> None:
        path = urlsplit(self.path).path
        try:
            try:
                methods = sorted(m for (m, p) in self.ROUTES if p == path)
                if not methods:
                    raise ApiError(404, "not_found", f"No route for path {path!r}")
                if self.command not in methods:
                    raise ApiError(
                        405,
                        "method_not_allowed",
                        f"{self.command} is not allowed on {path}",
                        headers={"Allow": ", ".join(methods)},
                    )
                handler = getattr(self, self.ROUTES[(self.command, path)])
                handler()
            except ApiError as exc:
                body: dict[str, t.Any] = {"error": exc.error, "message": exc.message}
                body.update(exc.details)
                self._send_json(exc.status, body, exc.headers)
            except Exception:
                logger.exception("unhandled error on %s %s", self.command, path)
                self._send_json(
                    500,
                    {"error": "internal_error", "message": "Unexpected server error"},
                )
        except OSError:
            # Client went away mid-response; nothing more to send.
            self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _dispatch

    # ----- helpers -----------------------------------------------------------

    def _send_json(
        self,
        status: int,
        body: dict[str, t.Any],
        headers: dict[str, str] | None = None,
    ) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, status: int, html: str) -> None:
        data = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, t.Any]:
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(
                411,
                "length_required",
                "Chunked request bodies are not supported; send Content-Length",
            )
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ApiError(411, "length_required", "Content-Length header is required")
        try:
            length = int(raw_length)
        except ValueError:
            raise ApiError(400, "bad_request", "Content-Length must be an integer")
        if length < 0:
            raise ApiError(400, "bad_request", "Content-Length must not be negative")
        if length > MAX_BODY_BYTES:
            raise ApiError(
                413,
                "payload_too_large",
                f"Request body exceeds the {MAX_BODY_BYTES} byte limit",
            )
        raw_body = self.rfile.read(length)
        if len(raw_body) != length:
            raise ApiError(400, "bad_request", "Request body was truncated")
        try:
            data = json.loads(raw_body, parse_constant=_reject_constant)
        except (ValueError, RecursionError):
            raise ApiError(400, "invalid_json", "Request body is not valid JSON")
        if not isinstance(data, dict):
            raise ApiError(400, "invalid_json", "Request body must be a JSON object")
        return data

    def _serializer(self, salt: str) -> URLSafeTimedSerializer:
        return URLSafeTimedSerializer(self.server.secret_key, salt=salt)  # type: ignore[attr-defined]

    # ----- endpoints ---------------------------------------------------------

    def _get_index(self) -> None:
        self._send_html(200, INDEX_HTML)

    def _get_health(self) -> None:
        self._send_json(200, {"status": "ok", "service": "demo_api"})

    def _post_sign(self) -> None:
        body = self._read_json_body()
        if "payload" not in body:
            raise ApiError(400, "missing_field", "'payload' is required")
        salt = _optional_salt(body)
        token = self._serializer(salt).dumps(body["payload"])
        self._send_json(200, {"token": token})

    def _post_verify(self) -> None:
        body = self._read_json_body()
        token = body.get("token")
        if not isinstance(token, str) or not token:
            raise ApiError(400, "missing_field", "'token' must be a non-empty string")
        salt = _optional_salt(body)
        max_age = body.get("max_age")
        if max_age is not None and (
            isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0
        ):
            raise ApiError(
                400,
                "invalid_field",
                "'max_age' must be a non-negative integer number of seconds",
            )
        try:
            payload, signed_at = self._serializer(salt).loads(
                token, max_age=max_age, return_timestamp=True
            )
        except SignatureExpired as exc:
            raise ApiError(
                401,
                "token_expired",
                f"Token has expired: {exc}",
                details={"signed_at": exc.date_signed.isoformat()}
                if exc.date_signed
                else None,
            )
        except BadSignature:
            raise ApiError(
                401,
                "invalid_signature",
                "Token signature is invalid or the token was modified",
            )
        except BadPayload:
            raise ApiError(400, "malformed_token", "Token payload could not be decoded")
        self._send_json(
            200,
            {
                "valid": True,
                "payload": payload,
                "signed_at": signed_at.isoformat(),
            },
        )


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], secret_key: str) -> None:
        self.secret_key = secret_key
        super().__init__(server_address, DemoRequestHandler)


def make_server(secret_key: str, host: str = "0.0.0.0", port: int = 8081) -> DemoServer:
    """Create a bound (not yet serving) server. Pass ``port=0`` for an ephemeral port."""
    return DemoServer((host, port), secret_key)
