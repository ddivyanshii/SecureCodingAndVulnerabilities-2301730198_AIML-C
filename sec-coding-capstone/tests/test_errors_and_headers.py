from library_app.security.authz import public


def test_security_headers_present(client):
    r = client.get("/login")
    h = r.headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY"
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["Cache-Control"] == "no-store"


def test_404_is_generic(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404 and "does not exist" in r.get_data(as_text=True)


def test_500_hides_internal_details(app):
    @app.route("/boom")
    @public
    def boom():
        raise RuntimeError("sqlite3.OperationalError: no such table: secret_internal_table")

    r = app.test_client().get("/boom")
    body = r.get_data(as_text=True)
    assert r.status_code == 500
    assert "Unable to process your request" in body
    assert "secret_internal_table" not in body and "Traceback" not in body
    assert "Reference:" in body


def test_500_details_are_logged(app, tmp_path):
    @app.route("/boom2")
    @public
    def boom2():
        raise RuntimeError("detail-for-the-log-only")

    app.test_client().get("/boom2")
    log_text = (tmp_path / "logs" / "app.log").read_text(encoding="utf-8")
    assert "detail-for-the-log-only" in log_text and "Traceback" in log_text


def test_request_body_size_limit(client):
    r = client.post("/login", data={"username": "a" * 50_000, "password": "x"})
    assert r.status_code == 413


def test_debug_mode_disabled(app):
    assert app.debug is False
