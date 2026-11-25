from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlsplit

from flask import abort, request, session

from library_app.security.audit import log_event

_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def get_csrf_token() -> str:
    token = session.get("csrf")
    if not isinstance(token, str) or not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def verify_csrf() -> None:
    if request.method not in _UNSAFE_METHODS:
        return

    origin = request.headers.get("Origin")
    if origin and origin != "null":
        if urlsplit(origin).netloc != request.host:
            log_event("CSRF_BAD_ORIGIN", "DENIED", f"origin={origin} path={request.path}")
            abort(400)

    expected = session.get("csrf")
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if (
        not isinstance(expected, str)
        or not isinstance(supplied, str)
        or not hmac.compare_digest(expected.encode(), supplied.encode())
    ):
        log_event("CSRF_INVALID", "DENIED", f"{request.method} {request.path}")
        abort(400)
