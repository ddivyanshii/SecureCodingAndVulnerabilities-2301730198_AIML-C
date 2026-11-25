import pytest

from library_app.security import validators as v


@pytest.mark.parametrize("raw,expected", [("CS101", "CS101"), (" cs101 ", "CS101"), ("MATH2001", "MATH2001")])
def test_book_code_valid(raw, expected):
    assert v.validate_book_code(raw) == expected


@pytest.mark.parametrize("raw", ["", "C101", "CS1", "CS10111", "CS-101", "CS101'; DROP TABLE books;--",
                                 "<script>", "CS\n101", "ＣＳ101"])
def test_book_code_invalid(raw):
    with pytest.raises(v.ValidationError):
        v.validate_book_code(raw)


@pytest.mark.parametrize("raw,expected", [("5", 5), ("1", 1), ("1000", 1000), (" 7 ", 7)])
def test_quantity_valid(raw, expected):
    assert v.validate_quantity(raw) == expected


@pytest.mark.parametrize("raw", [
    "0", "-5", "+5", "1001", "5.0", "1e3", "0x10", "5abc", "", None, " ",
    "999999999999999999999999",
    "٥",
    "²",
])
def test_quantity_invalid(raw):
    with pytest.raises(v.ValidationError):
        v.validate_quantity(raw)


@pytest.mark.parametrize("raw", ["Python Basics", "C++ Primer", "Data Structures: An Intro", "O'Reilly's Guide"])
def test_title_valid(raw):
    assert v.validate_title(raw) == raw


@pytest.mark.parametrize("raw", ["<script>alert(1)</script>", "x\"; DROP", "a", "A" * 121, "Book\r\nInjected"])
def test_title_invalid(raw):
    with pytest.raises(v.ValidationError):
        v.validate_title(raw)


def test_category_whitelist():
    assert v.validate_category("Physics") == "Physics"
    for bad in ["physics", "Hacking", "Physics' OR 1=1", ""]:
        with pytest.raises(v.ValidationError):
            v.validate_category(bad)


@pytest.mark.parametrize("raw", ["Ravi Kumar", "Priya", "Anna Maria Lopez"])
def test_name_valid(raw):
    assert v.validate_full_name(raw) == raw


@pytest.mark.parametrize("raw", ["R2D2", "Robert'); DROP TABLE users;--", "A", "<b>x</b>"])
def test_name_invalid(raw):
    with pytest.raises(v.ValidationError):
        v.validate_full_name(raw)


def test_roll_number():
    assert v.validate_roll_number("2023cse001") == "2023CSE001"
    for bad in ["123", "2023-CSE-001", "2023CSE0012345", "' OR '1'='1"]:
        with pytest.raises(v.ValidationError):
            v.validate_roll_number(bad)


def test_email():
    assert v.validate_email("Ravi.K@College.Example") == "ravi.k@college.example"
    for bad in ["ravi", "ravi@", "@x.com", "a@b", "a b@c.com", "a@b.c"]:
        with pytest.raises(v.ValidationError):
            v.validate_email(bad)


def test_password_policy():
    assert v.validate_password("Secure#2026", username="ravi")
    for bad in ["short1", "allletters", "12345678", "password1", "x" * 129 + "1"]:
        with pytest.raises(v.ValidationError):
            v.validate_password(bad)
    with pytest.raises(v.ValidationError):
        v.validate_password("ravi12345", username="ravi")


def test_search_field_whitelist_returns_trusted_column():
    assert v.validate_search_field("code") == "book_code"
    with pytest.raises(v.ValidationError):
        v.validate_search_field("title; DROP TABLE books")


def test_like_escaping():
    assert v.escape_like("100%_off") == "100\\%\\_off"


@pytest.mark.parametrize("target,ok", [
    ("/admin/books", True), ("/my-books?x=1", True),
    ("https://evil.example", False), ("//evil.example", False), ("/\\evil.example", False),
    ("javascript:alert(1)", False), ("", False),
])
def test_safe_redirect(target, ok):
    assert v.is_safe_redirect(target) is ok
