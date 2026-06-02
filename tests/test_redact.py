"""Redaction is the safety boundary for code sent to remote AI providers.

These cases pin the leaks the v2 hardening closed: a weak/named password, a
passphrase, a password containing '@' inside a connection URL, and provider keys —
all of which the previous entropy-only redactor passed through unmasked. The bias
is deliberately toward over-masking, but it must NOT mangle ordinary code.
"""

from __future__ import annotations

from njordscan.explain.redact import redact


def test_named_secrets_are_masked_even_when_low_entropy():
    # Each of these slipped past the old entropy>=3.6 gate.
    cases = [
        ('const password = "hunter2supersecretpwd"', "hunter2"),
        ('const pw = "P@ssw0rd123"', "P@ssw0rd"),
        ('PASSPHRASE = "correct horse battery staple"', "battery staple"),
        ('client_secret: "8b7c6d5e4f3a2b1c0d9e8f7a"', "8b7c6d5e"),
        ('auth_token = "letmein-please-1234"', "letmein-please"),
    ]
    for code, secret in cases:
        out = redact(code)
        assert secret not in out, f"leaked {secret!r}: {code!r} -> {out!r}"
        assert "‹redacted" in out


def test_backtick_template_literals_are_masked():
    # Backticks are the idiomatic modern-JS string; a 16-char random value also sits
    # below the entropy rule's 20-char floor, so the name rule must catch it.
    cases = [
        ("const dbPassword = `pX9mK2qL7nR4tW1z`", "pX9mK2qL7nR4tW1z"),
        ("const apiKey = `pX9mK2qL7nR4tW1z`", "pX9mK2qL7nR4tW1z"),
        ("const clientSecret = `Gx7Lp2Qm9Rn4Tv6Wz1`", "Gx7Lp2Qm9Rn4Tv6Wz1"),
    ]
    for code, secret in cases:
        out = redact(code)
        assert secret not in out, f"leaked {secret!r}: {code!r} -> {out!r}"
    # a benign backtick string is left alone
    assert redact("const greeting = `hello there`") == "const greeting = `hello there`"


def test_provider_key_shapes_are_masked():
    # Build the fake keys at runtime so this test file contains no committable
    # provider-key literal (GitHub push protection blocks even fake ones).
    stripe = "sk_" + "live_" + "a3f9c2b18d7e6f5a4b3c2d1e0f9a8b7c"
    aws = "wJalrXUt" + "nFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    akia = "AK" + "IA" + "1234567890ABCDEF"
    for code, token in [
        (f'const k = "{stripe}"', "live_a3f9c2b1"),
        (f'AWS_SECRET = "{aws}"', "wJalrXUt"),
        (f'id = "{akia}"', akia),
    ]:
        assert token not in redact(code), code


def test_url_credentials_with_at_sign_in_password_are_fully_masked():
    # The old regex stopped at the first '@' and leaked the rest of the password.
    code = 'DATABASE_URL = "postgres://user:p@ss0rd-with-at@db.internal:5432/prod"'
    out = redact(code)
    assert "p@ss0rd-with-at" not in out
    assert "‹redacted›" in out


def test_ordinary_code_is_not_over_masked():
    benign = [
        'const author = "Jane Doe"',
        'const keyboard = "qwerty layout"',
        'function getName(req) { return req.query.name }',
        'res.redirect(allowList.includes(dest) ? dest : "/")',
        'const message = "hello world this is fine"',
    ]
    for code in benign:
        assert redact(code) == code, f"over-masked: {code!r} -> {redact(code)!r}"


def test_empty_input_is_safe():
    assert redact("") == ""
