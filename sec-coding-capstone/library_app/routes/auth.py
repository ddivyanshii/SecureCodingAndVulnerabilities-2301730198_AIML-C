from __future__ import annotations

from flask import (Blueprint, current_app, flash, g, redirect, render_template, request,
                   url_for)

from library_app.security import validators as v
from library_app.security.audit import client_ip, log_event
from library_app.security.authz import login_required, public
from library_app.security.rate_limit import RateLimiter
from library_app.security.sessions import create_session, destroy_session
from library_app.services import ServiceError
from library_app.services import auth_service

bp = Blueprint("auth", __name__)


def _limiter() -> RateLimiter:
    ext = current_app.extensions
    if "login_limiter" not in ext:
        ext["login_limiter"] = RateLimiter(
            current_app.config["LOGIN_RATE_LIMIT"], current_app.config["LOGIN_RATE_WINDOW"]
        )
    return ext["login_limiter"]


def _home_for(user) -> str:
    return url_for("librarian.dashboard") if user.is_librarian else url_for("student.dashboard")


@bp.get("/")
@public
def index():
    if g.user is None:
        return redirect(url_for("auth.login"))
    return redirect(_home_for(g.user))


@bp.route("/register", methods=["GET", "POST"])
@public
def register():
    if g.user is not None:
        return redirect(_home_for(g.user))
    form = {k: request.form.get(k, "") for k in ("username", "full_name", "email", "roll_number")}
    errors: dict[str, str] = {}

    if request.method == "POST":
        clean: dict[str, str] = {}
        for field, fn in (("username", v.validate_username), ("full_name", v.validate_full_name),
                          ("email", v.validate_email), ("roll_number", v.validate_roll_number)):
            try:
                clean[field] = fn(request.form.get(field))
            except v.ValidationError as exc:
                errors[field] = exc.message
        password = request.form.get("password", "")
        try:
            v.validate_password(password, username=clean.get("username", ""))
            if password != request.form.get("confirm_password", ""):
                raise v.ValidationError("password", "Passwords do not match.")
        except v.ValidationError as exc:
            errors["password"] = exc.message

        if not errors:
            try:
                auth_service.register_student(password=password, **clean)
            except ServiceError as exc:
                errors["form"] = exc.message
            else:
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("auth.login"))
        else:
            log_event("REGISTER", "FAILURE", "validation failed: " + ",".join(sorted(errors)))

    status = 400 if errors else 200
    return render_template("auth/register.html", form=form, errors=errors), status


@bp.route("/login", methods=["GET", "POST"])
@public
def login():
    if g.user is not None:
        return redirect(_home_for(g.user))
    error = None
    username_raw = request.form.get("username", "")

    if request.method == "POST":
        if not _limiter().hit(client_ip()):
            log_event("LOGIN_RATE_LIMIT", "DENIED", "too many attempts from this IP")
            return render_template("auth/login.html", username="",
                                   error="Too many login attempts. Please wait a few minutes."), 429
        try:
            username = v.validate_username(username_raw)
            password = request.form.get("password", "")
            if not isinstance(password, str) or not 1 <= len(password) <= 128:
                raise ServiceError(auth_service.GENERIC_LOGIN_ERROR)
            user_id = auth_service.authenticate(username, password)
        except v.ValidationError:
            log_event("LOGIN", "FAILURE", "malformed username", username=username_raw)
            error = auth_service.GENERIC_LOGIN_ERROR
        except ServiceError as exc:
            error = exc.message
        else:
            create_session(user_id)
            target = request.args.get("next", "")
            if v.is_safe_redirect(target):
                return redirect(target)
            return redirect(url_for("auth.index"))

    status = 401 if error else 200
    return render_template("auth/login.html", username=username_raw[:20], error=error), status


@bp.post("/logout")
@login_required
def logout():
    log_event("LOGOUT", "SUCCESS")
    destroy_session()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
