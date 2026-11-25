from __future__ import annotations

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from library_app.security import validators as v
from library_app.security.audit import log_event
from library_app.security.authz import roles_required
from library_app.services import ServiceError, book_service, loan_service

bp = Blueprint("librarian", __name__, url_prefix="/admin")


@bp.get("/")
@roles_required("librarian")
def dashboard():
    return render_template("librarian/dashboard.html", stats=loan_service.dashboard_stats())


@bp.get("/books")
@roles_required("librarian")
def books():
    return render_template("librarian/books.html", books=book_service.list_books())


@bp.route("/addBook", methods=["GET", "POST"])
@roles_required("librarian")
def add_book():
    form = {k: request.form.get(k, "") for k in ("book_code", "title", "author", "category", "quantity")}
    errors: dict[str, str] = {}
    if request.method == "POST":
        clean: dict = {}
        for field, fn in (("book_code", v.validate_book_code), ("title", v.validate_title),
                          ("author", v.validate_author), ("category", v.validate_category),
                          ("quantity", v.validate_quantity)):
            try:
                clean[field] = fn(request.form.get(field))
            except v.ValidationError as exc:
                errors[field] = exc.message
        if not errors:
            try:
                book_service.add_book(**clean)
            except ServiceError as exc:
                errors["form"] = exc.message
            else:
                flash(f"Book {clean['book_code']} added.", "success")
                return redirect(url_for("librarian.books"))
        else:
            log_event("BOOK_ADD", "FAILURE", "validation failed: " + ",".join(sorted(errors)))
    return render_template("librarian/add_book.html", form=form, errors=errors,
                           categories=v.CATEGORIES), (400 if errors else 200)


@bp.post("/addCopies")
@roles_required("librarian")
def add_copies():
    try:
        book_id = v.validate_record_id(request.form.get("book_id"), "book_id")
        extra = v.validate_bounded_int(request.form.get("copies"), "copies", minimum=1, maximum=100)
        book_service.add_copies(book_id, extra)
    except v.ValidationError as exc:
        log_event("BOOK_ADD_COPIES", "FAILURE", exc.message)
        flash(exc.message, "error")
    except ServiceError as exc:
        log_event("BOOK_ADD_COPIES", "FAILURE", exc.message)
        flash(exc.message, "error")
    else:
        flash("Stock updated.", "success")
    return redirect(url_for("librarian.books"))


@bp.post("/deleteBook")
@roles_required("librarian")
def delete_book():
    try:
        book_id = v.validate_record_id(request.form.get("book_id"), "book_id")
        code = book_service.delete_book(book_id)
    except (v.ValidationError, ServiceError) as exc:
        log_event("BOOK_DELETE", "FAILURE", exc.message)
        flash(exc.message, "error")
    else:
        flash(f"Book {code} removed.", "success")
    return redirect(url_for("librarian.books"))


@bp.route("/issueBook", methods=["GET", "POST"])
@roles_required("librarian")
def issue_book():
    form = {k: request.form.get(k, "") for k in ("book_code", "roll_number")}
    errors: dict[str, str] = {}
    if request.method == "POST":
        clean: dict = {}
        for field, fn in (("book_code", v.validate_book_code), ("roll_number", v.validate_roll_number)):
            try:
                clean[field] = fn(request.form.get(field))
            except v.ValidationError as exc:
                errors[field] = exc.message
        if not errors:
            try:
                loan_service.issue_book(librarian_id=g.user.id, **clean)
            except ServiceError as exc:
                errors["form"] = exc.message
                log_event("BOOK_ISSUE", "FAILURE", exc.message)
            else:
                flash(f"Issued {clean['book_code']} to {clean['roll_number']}.", "success")
                return redirect(url_for("librarian.loans"))
    return render_template("librarian/issue_book.html", form=form, errors=errors), (400 if errors else 200)


@bp.get("/loans")
@roles_required("librarian")
def loans():
    return render_template("librarian/loans.html", loans=loan_service.active_loans())


@bp.post("/returnBook")
@roles_required("librarian")
def return_book():
    try:
        loan_id = v.validate_record_id(request.form.get("loan_id"), "loan_id")
        loan_service.return_book(loan_id=loan_id, librarian_id=g.user.id)
    except (v.ValidationError, ServiceError) as exc:
        log_event("BOOK_RETURN", "FAILURE", exc.message)
        flash(exc.message, "error")
    else:
        flash("Book returned.", "success")
    return redirect(url_for("librarian.loans"))


@bp.get("/activity")
@roles_required("librarian")
def activity():
    return render_template("librarian/activity.html", events=loan_service.recent_activity(200))
