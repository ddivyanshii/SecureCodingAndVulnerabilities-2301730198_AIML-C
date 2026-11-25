from __future__ import annotations

from flask import Blueprint, g, render_template, request

from library_app.security import validators as v
from library_app.security.audit import log_event
from library_app.security.authz import login_required, roles_required
from library_app.services import book_service, loan_service

bp = Blueprint("student", __name__)


@bp.get("/dashboard")
@roles_required("student")
def dashboard():
    loans = loan_service.loans_for_student(g.user.id)
    active = [loan for loan in loans if loan["returned_at"] is None]
    return render_template("student/dashboard.html", active=active)


@bp.get("/books/search")
@login_required
def search():
    results, error = None, None
    q_raw = request.args.get("q")
    field_raw = request.args.get("field", "title")
    q = ""
    if q_raw is not None:
        try:
            q = v.validate_search_query(q_raw)
            column = v.validate_search_field(field_raw)
            results = book_service.search_books(column, q)
        except v.ValidationError as exc:
            error = exc.message
            log_event("SEARCH_REJECTED", "FAILURE", f"field={field_raw!r} q={q_raw!r}")
    return render_template(
        "student/search.html", results=results, error=error,
        q=(q_raw or "")[:50], field=field_raw if field_raw in v.SEARCH_FIELDS else "title",
    ), (400 if error else 200)


@bp.get("/my-books")
@roles_required("student")
def my_books():
    loans = loan_service.loans_for_student(g.user.id)
    return render_template("student/my_books.html", loans=loans)
