# Signing Service Demo: Delivery Report

Date: 2026-10-12
Branch: `kencode/3bda0d9a`
Requested by: demo kenome (demo@kenome.ai, More Expensive LLM)

## 1. Summary

A small internal HTTP service in `demo_api/` exposes itsdangerous' `URLSafeTimedSerializer` so other teams can issue and verify tamper-proof tokens without embedding the library. It uses only the Python standard library, listens on port 8081, reads its key from `DEMO_SECRET`, and logs every request.

| Item | Result |
|---|---|
| Smoke test (`scripts/smoke_test.py`) | 6/6 checks passed against the running service |
| `demo_api` automated tests | 65 passed |
| Project configured suite (`pytest` with the project's ignores) | 131 passed |
| Robustness review findings | 2 genuine, both fixed and covered by regression tests |
| Independent review | Not completed as independent (see section 6) |

## 2. Codebase review: how the library works

**`Signer`** (`src/itsdangerous/signer.py`) produces `value.signature`. The signature is an HMAC over the value, keyed with a key derived from the secret and salt (`key_derivation`, default `django-concat`). `unsign` recomputes the HMAC and compares it in constant time, raising `BadSignature` on mismatch.

**`TimestampSigner`** (`src/itsdangerous/timed.py`) extends `Signer`. `sign` appends a base64 timestamp: `value.timestamp.signature`, where the timestamp counts seconds since a fixed epoch at one-second resolution. The signature covers the timestamp, so it cannot be changed without invalidating the token. `unsign(value, max_age)` checks the signature first, then computes `age = now - timestamp`. If `max_age` is set and `age > max_age`, it raises `SignatureExpired`, which carries the signing time. Expiry is therefore enforced at verification time from the signed timestamp, not stored state. Because of the one-second resolution, a token can be accepted up to a second past its nominal age.

**`URLSafeTimedSerializer`** (`src/itsdangerous/url_safe.py`, `serializer.py`) combines the two. `dumps` serialises the object to JSON, base64url-encodes it, and signs it with `TimestampSigner`. `loads(token, max_age=..., return_timestamp=...)` verifies the signature and expiry, then decodes the payload. Failures map to `BadSignature` (tampered or wrong key/salt), `SignatureExpired` (valid but too old) and `BadPayload` (signed but undecodable).

## 3. Design

- **Stdlib only.** `http.server.ThreadingHTTPServer` with a `BaseHTTPRequestHandler` subclass. No new dependencies in `pyproject.toml`.
- **Routing.** A `(method, path)` table in `DemoRequestHandler.ROUTES`. An unknown path returns 404. A known path with the wrong method returns 405 with an `Allow` header.
- **Errors.** Every error is a JSON body `{"error": <code>, "message": <text>}`. Expired and invalid tokens use distinct codes (`token_expired` and `invalid_signature`), both 401.
- **Bodies.** Only JSON objects are accepted. Bodies are capped at 64 KiB (`MAX_BODY_BYTES`). `Content-Length` is required and must be ASCII digits. Chunked bodies are rejected with 411.
- **Logging.** One line per request: `method`, `path` (query string excluded), `status`, `duration_ms`. Unhandled exceptions are logged with a traceback and return a generic 500 that does not leak detail.
- **Key handling.** `DEMO_SECRET` is required; the process exits with code 2 if it is missing or empty. The key is never logged or returned.
- **Files.** `demo_api/app.py` (handler and server), `demo_api/page.py` (HTML page), `demo_api/__main__.py` (entry point, `python -m demo_api`), `demo_api/__init__.py`.

## 4. Endpoint reference

| Method | Path | Request | Success | Errors |
|---|---|---|---|---|
| GET | `/health` | none | 200 `{"status": "ok", "service": "demo_api"}` | 405 on other methods |
| GET | `/` | none | 200 HTML page for signing and verifying text | 405 |
| POST | `/sign` | `{"payload": <any JSON>, "salt": "<optional non-empty string>"}` | 200 `{"token": "..."}` | 400 `missing_field`, `invalid_field`, `invalid_json`, `invalid_payload`; 411 `length_required`; 413 `payload_too_large` |
| POST | `/verify` | `{"token": "...", "salt": "<optional>", "max_age": <optional non-negative int>}` | 200 `{"valid": true, "payload": ..., "signed_at": "<ISO 8601>"}` | 401 `invalid_signature`; 401 `token_expired` (with `signed_at`); 400 `malformed_token`, `missing_field`, `invalid_field`, `invalid_json`; 411; 413 |
| any | unknown path | any | none | 404 `not_found` |
| other | known path | e.g. PUT, DELETE | none | 405 `method_not_allowed` with `Allow` header |
| HEAD, OPTIONS | any | | none | 501 or 405 from the stdlib default |

Default salt is `demo-api`. Callers that pass a `salt` to `/sign` must pass the same salt to `/verify`, or the token is rejected with `invalid_signature`.

## 5. Request traffic summary

The smoke test ran against the live service on 127.0.0.1:8081. Every check matched its expected status and error code.

| Check | Request | Status | Result |
|---|---|---|---|
| health | GET /health | 200 | PASS |
| sign | POST /sign | 200 | PASS (token issued) |
| verify valid | POST /verify | 200 | PASS (payload round-trips) |
| verify tampered | POST /verify, one signature character changed | 401 `invalid_signature` | PASS |
| verify expired | POST /sign, wait 2.1 s, POST /verify with `max_age: 1` | 401 `token_expired` | PASS |
| unknown route | GET /does-not-exist | 404 `not_found` | PASS |

The service request log matches the smoke run line for line, for example:

```
method=GET  path='/health'          status=200 duration_ms=0.48
method=POST path='/sign'            status=200 duration_ms=0.67
method=POST path='/verify'          status=200 duration_ms=0.36
method=POST path='/verify'          status=401 duration_ms=0.35   (tampered)
method=POST path='/verify'          status=401 duration_ms=0.50   (expired)
method=GET  path='/does-not-exist'  status=404 duration_ms=0.25
```

Durations for these requests were 0.25 to 0.7 ms. The probe run added malformed-input requests (bad JSON, non-object bodies, oversized body 413, missing Content-Length 411, bad Content-Length 400, unsupported methods 405 and 501, a long request line 414). All were logged with the correct status.

The captured API traffic (`api_trace` filtered to port 8081) returned no entries for these local calls, so it does not corroborate the run. The service's own request log is the evidence used here.

## 6. Test results

- `tests/test_demo_api/test_app.py`: **65 passed**. Covers every endpoint and error case: sign payload types and salts; verify valid, tampered, wrong key, wrong salt, garbage, expired, distinct error codes, undecodable payload, `max_age` validation; request body handling (invalid JSON, non-object bodies, empty body, oversized, missing/bad/negative Content-Length, underscore Content-Length, chunked, truncated); routing (404, 405 with Allow, unsupported methods, query string handling); a forced 500; and request logging, including that the query string is excluded from the logged path.
- Full configured suite (`python3 -m pytest -q --ignore=tests/test_itsdangerous/test_timed.py --ignore=tests/test_itsdangerous/test_url_safe.py`): **131 passed**.
- `tests/test_itsdangerous/test_timed.py` and `test_url_safe.py` are excluded by the project configuration. They fail at collection with `ModuleNotFoundError: No module named 'freezegun'`, a dependency missing from this devbox. This is independent of the signing service and was not changed.
- Known limitation: the smoke test's expired-token check relies on a 2.1 s sleep. Timestamps have one-second resolution, so this is deliberate but adds about 2 s to the run.

## 7. Review findings and resolutions

The review was done by the lead engineer (self-review, not independent). An explorer sub-agent was dispatched for an independent review, but its dispatch returned `403 Forbidden` from the agent runtime and produced no output, so **the review is not independent**. A second, independent review is recommended before production use.

| # | Finding | Severity | Evidence | Resolution |
|---|---|---|---|---|
| 1 | `POST /sign` with a JSON string containing a lone surrogate (`{"payload": "\ud800"}`) returned 500 with a traceback in the log, because UTF-8 encoding fails inside the serializer. | Medium | Reproduced against the running service; log shows `UnicodeEncodeError` | Fixed in `demo_api/app.py`: encoding errors now return 400 `invalid_payload`. Regression test `test_sign_unencodable_payload_is_400`. Commit `a8d7a38`. |
| 2 | `Content-Length` was parsed with `int()`, which accepts `1_0` and `+5`, so non-HTTP forms were accepted. | Low | Reproduced with a raw socket request | Fixed: `Content-Length` must match `[0-9]+`. Regression test `test_content_length_with_underscore_is_rejected`. Commit `a8d7a38`. |

Probed and found correct, with no change needed: nested JSON to depth 900 signs and verifies; depth 5000 is rejected with 400; a 5000-digit integer is rejected with 400 (Python's integer-length limit); `NaN` is rejected with 400 (`parse_constant`); non-UTF-8 request bytes return 400; a body over 64 KiB returns 413; a request line of 70 KB returns 414; OPTIONS returns 405 and HEAD returns 501; a malformed request line returns 400 with a JSON body.

## 8. Commit history

| Commit | Subject | Contents |
|---|---|---|
| `ade213b` | Add itsdangerous signing service and smoke test | `demo_api/` package (service, page, entry point) and `scripts/smoke_test.py` |
| `062bf95` | Add automated tests for the signing service | `tests/test_demo_api/test_app.py` (63 tests at this commit) |
| `a8d7a38` | Harden signing service against malformed input | Fixes for findings 1 and 2, plus regression tests |
| (this commit) | Add delivery report | `DEMO_REPORT.md` |

Base branch history: `672971d Merge branch 'stable'`.

## 9. Operational notes

- Run: `DEMO_SECRET=<secret> PYTHONPATH=src:. python3 -m demo_api` (the package imports `itsdangerous` from `src/`).
- The smoke run used a throwaway secret, `smoke-test-secret-do-not-use-in-prod`, set only in the devbox process environment. Production must supply its own secret.
- The service is a single process with `ThreadingHTTPServer`. It is not hardened for direct internet exposure: it has no TLS, no authentication, no rate limiting, and no CORS policy. It is intended for internal use behind existing network controls.

## 10. Process issues

- During the review step I ran a `git checkout` on the wrong ref, which detached HEAD and removed the tracked service files from the working tree. Nothing was committed or lost: all work is in the three commits above. I restored the session branch with `git checkout -f kencode/3bda0d9a`, which also removed a stray untracked `tests/test_demo_api/__init__.py` I had created by mistake. Tests were re-run after the restore and pass.
- Several parallel `edit_file` calls on the same file collided and partially applied. I verified each file's contents after the collisions and reapplied the missing edits one at a time.
