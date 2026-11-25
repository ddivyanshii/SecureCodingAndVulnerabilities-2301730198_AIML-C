from __future__ import annotations

from flask import Response, current_app, g, request

CSP = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)


def apply_security_headers(response: Response) -> Response:
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Frame-Options"] = "DENY"
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "same-origin"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if g.get("user") is not None or request.endpoint in ("auth.login", "auth.register"):
        h["Cache-Control"] = "no-store"
        h["Pragma"] = "no-cache"
    if current_app.config.get("SESSION_COOKIE_SECURE"):
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    h.pop("Server", None)
    return response
