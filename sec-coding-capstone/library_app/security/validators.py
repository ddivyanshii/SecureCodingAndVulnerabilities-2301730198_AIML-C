from __future__ import annotations

import re
from urllib.parse import urlsplit

CATEGORIES: tuple[str, ...] = (
    "Computer Science",
    "Electronics",
    "Mathematics",
    "Physics",
    "Mechanical",
    "Civil",
    "Management",
    "General",
)
SEARCH_FIELDS: dict[str, str] = {
    "title": "title",
    "author": "author",
    "code": "book_code",
}
ROLES: tuple[str, ...] = ("student", "librarian")

_A = re.ASCII
USERNAME_RE = re.compile(r"[a-z][a-z0-9_]{3,19}", _A)
FULL_NAME_RE = re.compile(r"[A-Za-z]+(?: [A-Za-z]+){0,4}", _A)
ROLL_NUMBER_RE = re.compile(r"[A-Z0-9]{10,12}", _A)
EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}",
    _A,
)
BOOK_CODE_RE = re.compile(r"[A-Z]{2,4}[0-9]{3,4}", _A)
TITLE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,:'&()+#\-]*", _A)
AUTHOR_RE = re.compile(r"[A-Za-z][A-Za-z .'\-]*", _A)
SEARCH_RE = re.compile(r"[A-Za-z0-9 .,:'&+#\-]*", _A)
DIGITS_RE = re.compile(r"[0-9]+", _A)

COMMON_PASSWORDS = frozenset(
    {
        "password", "password1", "password123", "12345678", "123456789",
        "qwerty123", "iloveyou", "admin123", "welcome1", "letmein1",
        "library123", "student123", "abc12345", "11111111", "passw0rd",
    }
)


class ValidationError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


def _as_text(raw: object, field: str, *, min_len: int, max_len: int) -> str:
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ValidationError(field, "Invalid value.")
    value = raw.strip()
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValidationError(field, "Contains invalid characters.")
    if min_len > 0 and not value:
        raise ValidationError(field, "This field is required.")
    if len(value) < min_len:
        raise ValidationError(field, f"Must be at least {min_len} characters.")
    if len(value) > max_len:
        raise ValidationError(field, f"Must be at most {max_len} characters.")
    return value


def _match(regex: re.Pattern[str], value: str, field: str, message: str) -> str:
    if not regex.fullmatch(value):
        raise ValidationError(field, message)
    return value


def validate_username(raw: object) -> str:
    value = _as_text(raw, "username", min_len=4, max_len=20).lower()
    return _match(USERNAME_RE, value, "username",
                  "4-20 characters: lowercase letters, digits, underscore; must start with a letter.")


def validate_full_name(raw: object) -> str:
    value = _as_text(raw, "full_name", min_len=2, max_len=60)
    value = " ".join(value.split())
    return _match(FULL_NAME_RE, value, "full_name", "Only letters and single spaces are allowed.")


def validate_roll_number(raw: object) -> str:
    value = _as_text(raw, "roll_number", min_len=10, max_len=12).upper()
    return _match(ROLL_NUMBER_RE, value, "roll_number", "Must be 10-12 letters or digits.")


def validate_email(raw: object) -> str:
    value = _as_text(raw, "email", min_len=6, max_len=254).lower()
    return _match(EMAIL_RE, value, "email", "Enter a valid email address.")


def validate_password(raw: object, *, username: str = "") -> str:
    if not isinstance(raw, str):
        raise ValidationError("password", "Invalid value.")
    if len(raw) < 8:
        raise ValidationError("password", "Must be at least 8 characters.")
    if len(raw) > 128:
        raise ValidationError("password", "Must be at most 128 characters.")
    if not re.search(r"[A-Za-z]", raw) or not re.search(r"[0-9]", raw):
        raise ValidationError("password", "Must contain at least one letter and one digit.")
    if raw.lower() in COMMON_PASSWORDS:
        raise ValidationError("password", "This password is too common.")
    if username and username.lower() in raw.lower():
        raise ValidationError("password", "Password must not contain the username.")
    return raw


def validate_book_code(raw: object) -> str:
    value = _as_text(raw, "book_code", min_len=5, max_len=8).upper()
    return _match(BOOK_CODE_RE, value, "book_code",
                  "Format: 2-4 letters followed by 3-4 digits (e.g. CS101).")


def validate_title(raw: object) -> str:
    value = " ".join(_as_text(raw, "title", min_len=2, max_len=120).split())
    return _match(TITLE_RE, value, "title",
                  "Letters, digits, spaces and . , : ' & ( ) + # - only.")


def validate_author(raw: object) -> str:
    value = " ".join(_as_text(raw, "author", min_len=2, max_len=80).split())
    return _match(AUTHOR_RE, value, "author", "Letters, spaces and . ' - only.")


def validate_category(raw: object) -> str:
    value = _as_text(raw, "category", min_len=1, max_len=40)
    if value not in CATEGORIES:
        raise ValidationError("category", "Choose a category from the list.")
    return value


def validate_bounded_int(raw: object, field: str, *, minimum: int, maximum: int) -> int:
    max_digits = len(str(maximum))
    value = _as_text(raw if raw is not None else "", field, min_len=1, max_len=max_digits + 2)
    if not DIGITS_RE.fullmatch(value) or len(value) > max_digits:
        raise ValidationError(field, f"Enter a whole number between {minimum} and {maximum}.")
    number = int(value)
    if not minimum <= number <= maximum:
        raise ValidationError(field, f"Enter a whole number between {minimum} and {maximum}.")
    return number


def validate_quantity(raw: object) -> int:
    return validate_bounded_int(raw, "quantity", minimum=1, maximum=1000)


def validate_record_id(raw: object, field: str = "id") -> int:
    return validate_bounded_int(raw, field, minimum=1, maximum=999_999_999)


def validate_search_query(raw: object) -> str:
    value = " ".join(_as_text(raw, "q", min_len=0, max_len=50).split())
    return _match(SEARCH_RE, value, "q", "Search may contain letters, digits, spaces and . , : ' & + # -")


def validate_search_field(raw: object) -> str:
    key = raw if isinstance(raw, str) and raw else "title"
    if key not in SEARCH_FIELDS:
        raise ValidationError("field", "Invalid search field.")
    return SEARCH_FIELDS[key]


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def is_safe_redirect(target: object) -> bool:
    if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
        return False
    if "\\" in target or any(ord(c) < 32 for c in target):
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc
