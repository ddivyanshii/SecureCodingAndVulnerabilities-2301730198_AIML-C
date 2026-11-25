from __future__ import annotations

import secrets as _secrets

import click
from flask import Flask, render_template, request
from werkzeug.exceptions import HTTPException

from library_app import db
from library_app.config import INSTANCE_DIR, build_config
from library_app.security import audit, authz, csrf, headers, sessions
from library_app.security import validators as v

_ERROR_MESSAGES = {
    400: ("Bad request", "The request could not be processed. Please reload the page and try again."),
    403: ("Access denied", "You do not have permission to access this page."),
    404: ("Not found", "The page you requested does not exist."),
    405: ("Method not allowed", "This action is not allowed."),
    413: ("Request too large", "The submitted data is too large."),
    429: ("Too many requests", "Please slow down and try again later."),
    500: ("Something went wrong", "Unable to process your request. Please try again later."),
}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_path=str(INSTANCE_DIR), instance_relative_config=False)
    app.config.update(build_config())
    if test_config:
        app.config.update(test_config)

    audit.configure_logging(app)
    db.init_app(app)

    app.before_request(sessions.load_current_user)
    app.before_request(authz.enforce_access_policy)
    app.before_request(csrf.verify_csrf)
    app.after_request(headers.apply_security_headers)

    app.jinja_env.globals["csrf_token"] = csrf.get_csrf_token
    app.jinja_env.autoescape = True

    from library_app.routes import auth, librarian, student

    app.register_blueprint(auth.bp)
    app.register_blueprint(student.bp)
    app.register_blueprint(librarian.bp)

    _register_error_handlers(app)
    _register_cli(app)

    with app.app_context():
        db.init_db()
    return app


def _register_error_handlers(app: Flask) -> None:
    def render_error(code: int, incident: str | None = None):
        title, message = _ERROR_MESSAGES.get(code, _ERROR_MESSAGES[500])
        return render_template("error.html", code=code, title=title, message=message,
                               incident=incident), code

    @app.errorhandler(HTTPException)
    def handle_http(exc: HTTPException):
        code = exc.code or 500
        if code in (403, 404, 405):
            audit.security_logger.info("http_%s %s %s", code, request.method,
                                       audit.sanitize_for_log(request.path, 200))
        return render_error(code if code in _ERROR_MESSAGES else 400)

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception):
        incident = _secrets.token_hex(4).upper()
        audit.app_logger.exception("Unhandled error incident=%s %s %s", incident, request.method,
                                   audit.sanitize_for_log(request.path, 200))
        return render_error(500, incident)


def _register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command() -> None:
        db.init_db()
        click.echo("Database initialised.")

    @app.cli.command("create-librarian")
    @click.option("--username", prompt=True)
    @click.option("--full-name", prompt=True)
    @click.option("--email", prompt=True)
    @click.password_option()
    def create_librarian_command(username: str, full_name: str, email: str, password: str) -> None:
        from library_app.services import auth_service

        try:
            username = v.validate_username(username)
            auth_service.create_librarian(
                username=username, full_name=v.validate_full_name(full_name),
                email=v.validate_email(email), password=v.validate_password(password, username=username),
            )
        except v.ValidationError as exc:
            raise click.ClickException(exc.message) from None
        except Exception:
            raise click.ClickException("Could not create librarian (duplicate username/email?).") from None
        click.echo(f"Librarian '{username}' created.")

    @app.cli.command("seed-demo")
    @click.option("--password", default=None, help="Password for all demo accounts (default: random).")
    def seed_demo_command(password: str | None) -> None:
        from library_app.seed import seed_demo

        if app.config["ENV_NAME"] == "production":
            raise click.ClickException("seed-demo is disabled in production.")
        for line in seed_demo(password):
            click.echo(line)

    @app.cli.command("purge-sessions")
    def purge_sessions_command() -> None:
        click.echo(f"Removed {sessions.purge_expired_sessions()} expired sessions.")
