from library_app.security import passwords


def test_hash_is_salted_and_not_plaintext():
    h1 = passwords.hash_password("Secure#2026")
    h2 = passwords.hash_password("Secure#2026")
    assert h1 != h2
    assert "Secure#2026" not in h1
    assert h1.startswith("scrypt$16384$8$1$")


def test_verify_correct_and_wrong():
    h = passwords.hash_password("Secure#2026")
    assert passwords.verify_password("Secure#2026", h)
    assert not passwords.verify_password("secure#2026", h)
    assert not passwords.verify_password("", h)


def test_verify_rejects_tampered_or_garbage_hashes():
    h = passwords.hash_password("Secure#2026")
    parts = h.split("$")
    assert not passwords.verify_password("Secure#2026", "$".join(["md5"] + parts[1:]))
    assert not passwords.verify_password("Secure#2026", "$".join([parts[0], str(2**30)] + parts[2:]))
    for garbage in ["", "plain", "scrypt$x$y$z$a$b", None]:
        assert not passwords.verify_password("Secure#2026", garbage)


def test_needs_rehash():
    assert not passwords.needs_rehash(passwords.hash_password("Secure#2026"))
    assert passwords.needs_rehash("scrypt$4096$8$1$AAAA$BBBB")
