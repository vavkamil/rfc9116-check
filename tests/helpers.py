"""Shared deterministic validation fixtures."""

from datetime import datetime, timezone

from securitytxt_scan.validation import validate_security_txt

NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
URL = "https://example.cz/.well-known/security.txt"


def validate(text: str, content_type: str = "text/plain; charset=utf-8"):
    return validate_security_txt(text.encode("utf-8"), content_type, URL, URL, now=NOW)
