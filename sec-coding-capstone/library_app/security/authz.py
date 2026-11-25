from __future__ import annotations

from functools import wraps
from typing import Callable, TypeVar

from flask import abort, current_app, flash, g, redirect, request, url_for

from library_app.security.audit import log_event
from library_app.security.validators import ROLES

F = TypeVar("F", bound=Callable)

_POLICY_ATTR = "_access_policy"
PUBLIC = "public"
AUTHENTICATED = "authenticated"


def public(view: F) -> F:
    setattr(view, _POLICY_ATTR, (PUBLIC,))
    return view


def _deny_unauthenticated():
    if g.get("session_expired"):
        flash("Your session expired due to inactivity. Please log in again.", "warning")
    else:
        flash("Please log in to continue.", "info")
    return redirect(url_for("auth.login", next=request.path))


def _deny_forbidden(required: tuple[str, ...]):
    log_event("AUTHZ_DENIED", "DENIED",
              f"{request.method} {request.path} requires={','.join(required)} role={g.user.role}")
    abort(403)


def login_required(view: F) -> F:
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.get("user") is None:
            return _deny_unauthenticated()
        return view(*args, **kwargs)

    setattr(wrapper, _POLICY_ATTR, (AUTHENTICATED,))
    return wrapper


def roles_required(*roles: str) -> Callable[[F], F]:
    unknown = set(roles) - set(ROLES)
    if not roles or unknown:
        raise ValueError(f"Unknown role(s): {unknown or 'none given'}")

    def decorator(view: F) -> F:
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.get("user") is None:
                return _deny_unauthenticated()
            if g.user.role not in roles:
                return _deny_forbidden(roles)
            return view(*args, **kwargs)

        setattr(wrapper, _POLICY_ATTR, roles)
        return wrapper

    return decorator


def policy_of(endpoint: str | None) -> tuple[str, ...] | None:
    if endpoint is None:
        return None
    if endpoint == "static":
        return (PUBLIC,)
    view = current_app.view_functions.get(endpoint)
    return getattr(view, _POLICY_ATTR, None)


def enforce_access_policy():
    if request.endpoint is None:
        return None
    policy = policy_of(request.endpoint)
    if policy is None:
        log_event("AUTHZ_NO_POLICY", "DENIED", f"endpoint={request.endpoint} has no access policy")
        abort(403)
    if policy == (PUBLIC,):
        return None
    if g.get("user") is None:
        return _deny_unauthenticated()
    if policy == (AUTHENTICATED,):
        return None
    if g.user.role not in policy:
        return _deny_forbidden(policy)
    return None
