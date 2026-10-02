"""Pragmatic RFC 9116 parsing and validation."""

from __future__ import annotations

import base64
import re
import unicodedata
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from email.message import Message
from typing import Any
from urllib.parse import urlsplit

from .well_known import REGISTERED_WELL_KNOWN_SUFFIXES

RFC9116_FIELDS = {
    "acknowledgments",
    "canonical",
    "contact",
    "encryption",
    "expires",
    "hiring",
    "policy",
    "preferred-languages",
}
# Fields added to the IANA registry after RFC 9116 was published. They remain
# optional; record their use without making the validator depend on their
# external specifications.
REGISTERED_EXTENSION_FIELDS = {"bug-bounty", "csaf"}
IANA_SECURITY_TXT_FIELDS_REGISTRY_DATE = "2026-03-07"
IANA_SECURITY_TXT_FIELDS_REGISTRY_URL = (
    "https://www.iana.org/assignments/security-txt-fields"
)
KNOWN_FIELDS = RFC9116_FIELDS | REGISTERED_EXTENSION_FIELDS
URI_FIELDS = RFC9116_FIELDS - {"expires", "preferred-languages"}
FIELD_LINE_RE = re.compile(r"^([\x21-\x39\x3b-\x7e]+): (.*)$")
EMPTY_FIELD_LINE_RE = re.compile(r"^([\x21-\x39\x3b-\x7e]+):[ \t]*$")
RFC3339_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$"
)
URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
MIME_TYPE_RE = re.compile(
    r"^\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+)/"
    r"([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?:\s*;|\s*$)"
)
LANGUAGE_TAG_RE = re.compile(
    r"""
    ^(?:
        (?:
            [A-Z]{2,3}(?:-[A-Z]{3}){0,3}
            |[A-Z]{4}
            |[A-Z]{5,8}
        )
        (?:-[A-Z]{4})?
        (?:-(?:[A-Z]{2}|[0-9]{3}))?
        (?:-(?:[A-Z0-9]{5,8}|[0-9][A-Z0-9]{3}))*
        (?:-[0-9A-WY-Z](?:-[A-Z0-9]{2,8})+)*
        (?:-X(?:-[A-Z0-9]{1,8})+)?
        |X(?:-[A-Z0-9]{1,8})+
    )$
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Registered ISO 639-1 language subtags. Three-letter primary subtags and
# structurally valid private-use/grandfathered tags are handled separately.
ISO_639_1 = frozenset(
    "aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo br bs ca ce "
    "ch co cr cs cu cv cy da de dv dz ee el en eo es et eu fa ff fi fj fo fr "
    "fy ga gd gl gn gu gv ha he hi ho hr ht hu hy hz ia id ie ig ii ik io is "
    "it iu ja jv ka kg ki kj kk kl km kn ko kr ks ku kv kw ky la lb lg li ln "
    "lo lt lu lv mg mh mi mk ml mn mr ms mt my na nb nd ne ng nl nn no nr nv "
    "ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd se sg si sk "
    "sl sm sn so sq sr ss st su sv sw ta te tg th ti tk tl tn to tr ts tt tw "
    "ty ug uk ur uz ve vi vo wa wo xh yi yo za zh zu".split()
)
DEPRECATED_LANGUAGE_SUBTAGS = frozenset({"in", "iw", "ji", "jw", "mo", "sh"})
GRANDFATHERED_LANGUAGE_TAGS = frozenset(
    {
        "art-lojban",
        "cel-gaulish",
        "en-gb-oed",
        "i-ami",
        "i-bnn",
        "i-default",
        "i-enochian",
        "i-hak",
        "i-klingon",
        "i-lux",
        "i-mingo",
        "i-navajo",
        "i-pwn",
        "i-tao",
        "i-tay",
        "i-tsu",
        "no-bok",
        "no-nyn",
        "sgn-be-fr",
        "sgn-be-nl",
        "sgn-ch-de",
        "zh-guoyu",
        "zh-hakka",
        "zh-min",
        "zh-min-nan",
        "zh-xiang",
    }
)


def parse_content_type(header: str | None) -> tuple[str | None, str | None]:
    """Parse an HTTP Content-Type without accepting malformed defaults."""
    if not header:
        return None, None
    message = Message()
    message["content-type"] = header
    raw_charset = message.get_param("charset")
    charset = raw_charset if isinstance(raw_charset, str) else None
    match = MIME_TYPE_RE.match(header)
    if not match:
        # email.message defaults malformed values to text/plain, which would
        # accidentally make an invalid Content-Type look RFC compliant.
        invalid_value = header.split(";", 1)[0].strip().lower() or "<invalid>"
        return invalid_value, charset
    return f"{match.group(1).lower()}/{match.group(2).lower()}", charset


def parse_rfc3339(value: str) -> datetime | None:
    """Parse an RFC 3339 timestamp, including offsets and leap seconds."""
    match = RFC3339_RE.fullmatch(value)
    if not match:
        return None
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    microsecond = int(((fraction or "") + "000000")[:6])
    leap_second = int(second) == 60
    normalized_second = 59 if leap_second else int(second)
    try:
        parsed = datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            normalized_second,
            microsecond,
        )
        if offset.lower() == "z":
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            sign = 1 if offset[0] == "+" else -1
            offset_hours, offset_minutes = map(int, offset[1:].split(":"))
            if offset_hours > 23 or offset_minutes > 59:
                return None
            parsed = parsed.replace(
                tzinfo=timezone(
                    sign * timedelta(hours=offset_hours, minutes=offset_minutes)
                )
            )
        if leap_second:
            parsed += timedelta(seconds=1)
        return parsed
    except ValueError:
        return None


def validate_uri(value: str) -> str | None:
    """Return a concise error when a field value is not an absolute URI."""
    if not URI_SCHEME_RE.match(value):
        return "not an absolute URI"
    if any(ord(char) < 0x20 or ord(char) == 0x7F or char.isspace() for char in value):
        return "contains whitespace or a control character"
    if any(ord(char) > 0x7F for char in value):
        return "contains a non-ASCII character instead of percent-encoding"
    if BAD_PERCENT_RE.search(value):
        return "contains invalid percent-encoding"
    try:
        parsed = urlsplit(value)
        if not parsed.scheme:
            return "does not have a URI scheme"
        if parsed.scheme.lower() in {"http", "https"} and not parsed.hostname:
            return "web URI does not have a hostname"
    except ValueError as exc:
        return str(exc)
    return None


def valid_language_tag(value: str) -> bool:
    """Validate RFC 5646 structure and registered two-letter languages."""
    lowered = value.lower()
    if lowered in GRANDFATHERED_LANGUAGE_TAGS:
        return True
    if not LANGUAGE_TAG_RE.fullmatch(value):
        return False
    if lowered.startswith("x-"):
        return True
    primary = lowered.split("-", 1)[0]
    if len(primary) == 2:
        return primary in ISO_639_1 or primary in DEPRECATED_LANGUAGE_SUBTAGS
    # Current registered primary language subtags are two or three letters;
    # four-letter values are reserved and longer values require registration.
    return len(primary) == 3 and primary.isalpha()


def unregistered_well_known_suffix(value: str) -> str | None:
    """Return an unregistered /.well-known/ suffix used by a web URI."""
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    prefix = "/.well-known/"
    if not parsed.path.startswith(prefix):
        return None
    suffix = parsed.path[len(prefix) :].split("/", 1)[0]
    if suffix in REGISTERED_WELL_KNOWN_SUFFIXES:
        return None
    return suffix or "<empty>"


def comparable_web_uri(value: str) -> tuple[Any, ...] | None:
    """Normalize harmless web-URI differences for Canonical comparisons."""
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or not parsed.hostname:
            return None
        port = parsed.port
    except ValueError:
        return None
    effective_port = port or (443 if scheme == "https" else 80)
    return (
        scheme,
        parsed.username,
        parsed.password,
        parsed.hostname.lower(),
        effective_port,
        parsed.path or "/",
        parsed.query,
        parsed.fragment,
    )


def extract_signed_payload(text: str) -> tuple[str, bool, list[str]]:
    """Extract cleartext from a basic OpenPGP clear-signed document."""
    marker = "-----BEGIN PGP SIGNED MESSAGE-----"
    if not text.startswith(marker):
        return text, False, []

    errors: list[str] = []
    lines = text.splitlines()
    try:
        blank_index = lines.index("")
    except ValueError:
        return "", True, ["invalid_pgp_cleartext_structure"]

    hash_headers = lines[1:blank_index]
    if not hash_headers or any(not line.startswith("Hash: ") for line in hash_headers):
        errors.append("invalid_pgp_hash_header")

    try:
        signature_start = lines.index("-----BEGIN PGP SIGNATURE-----", blank_index + 1)
        signature_end = lines.index("-----END PGP SIGNATURE-----", signature_start + 1)
    except ValueError:
        return "", True, [*errors, "invalid_pgp_signature_structure"]

    if signature_end != len(lines) - 1:
        errors.append("content_after_pgp_signature")

    cleartext_lines = lines[blank_index + 1 : signature_start]
    unescaped = [
        line[2:] if line.startswith("- ") else line for line in cleartext_lines
    ]
    return "\n".join(unescaped) + "\n", True, errors


def validate_security_txt(
    body: bytes,
    content_type_header: str | None,
    requested_url: str,
    final_url: str,
    *,
    now: datetime | None = None,
    extra_errors: Iterable[str] = (),
) -> dict[str, Any]:
    """Perform pragmatic validation of the RFC 9116 MUST-level requirements."""
    now = now or datetime.now(timezone.utc)
    errors: list[str] = list(extra_errors)
    warnings: list[str] = []
    info: list[str] = []
    fields: dict[str, list[str]] = {}
    unknown_fields: list[str] = []
    extension_fields: list[str] = []
    registered_extension_fields: list[str] = []

    media_type, charset = parse_content_type(content_type_header)
    if media_type is None:
        errors.append("missing_content_type")
    elif media_type != "text/plain":
        errors.append("content_type_not_text_plain")
    if charset is None:
        errors.append("missing_utf8_charset")
    elif charset.lower() != "utf-8":
        errors.append("charset_not_utf8")

    if urlsplit(final_url).scheme.lower() != "https":
        errors.append("final_url_not_https")
    if not body:
        errors.append("empty_body")

    try:
        text = body.decode("utf-8", errors="strict")
        utf8_valid = True
    except UnicodeDecodeError:
        text = ""
        utf8_valid = False
        errors.append("invalid_utf8")

    signed = False
    expires_at: str | None = None
    expired: bool | None = None
    if utf8_valid:
        if text.startswith("\ufeff"):
            errors.append("utf8_bom_before_first_line")
        if unicodedata.normalize("NFC", text) != text:
            warnings.append("not_unicode_nfc")
        if re.search(r"\r(?!\n)", text):
            errors.append("invalid_line_separator")
        if text and not text.endswith("\n"):
            errors.append("missing_final_line_separator")
        if any(
            (ord(char) < 0x20 and char not in {"\t", "\r", "\n"})
            or 0x7F <= ord(char) <= 0x9F
            or char in {"\u2028", "\u2029"}
            for char in text
        ):
            errors.append("disallowed_control_character")
        if any(unicodedata.category(char) == "Cn" for char in text):
            errors.append("unassigned_unicode_code_point")

        payload, signed, signature_errors = extract_signed_payload(text)
        errors.extend(signature_errors)
        if signed:
            info.append("pgp_present")

        for line_number, raw_line in enumerate(payload.splitlines(), start=1):
            line = raw_line.rstrip(" \t")
            if not line.strip(" \t") or line.startswith("#"):
                continue
            empty_match = EMPTY_FIELD_LINE_RE.fullmatch(raw_line)
            if empty_match:
                original_name = empty_match.group(1)
                name = original_name.lower()
                errors.append(f"empty_field_value:{original_name}")
                if name not in RFC9116_FIELDS:
                    extension_fields.append(original_name)
                if name in REGISTERED_EXTENSION_FIELDS:
                    registered_extension_fields.append(original_name)
                elif name not in KNOWN_FIELDS:
                    unknown_fields.append(original_name)
                continue
            match = FIELD_LINE_RE.fullmatch(line)
            if not match:
                errors.append(f"malformed_line:{line_number}")
                continue

            original_name, value = match.groups()
            name = original_name.lower()
            fields.setdefault(name, []).append(value)
            if name not in RFC9116_FIELDS:
                extension_fields.append(original_name)
            if name in REGISTERED_EXTENSION_FIELDS:
                registered_extension_fields.append(original_name)
            elif name not in KNOWN_FIELDS:
                unknown_fields.append(original_name)

        contacts = fields.get("contact", [])
        if not contacts:
            errors.append("missing_contact")

        expires_values = fields.get("expires", [])
        if not expires_values:
            errors.append("missing_expires")
        elif len(expires_values) > 1:
            errors.append("multiple_expires")
        else:
            expires = parse_rfc3339(expires_values[0])
            if expires is None:
                errors.append("invalid_expires_rfc3339")
            else:
                expires_at = expires.isoformat()
                expired = expires <= now
                if expired:
                    errors.append("expired")
                elif expires >= now + timedelta(days=365):
                    warnings.append("expires_more_than_one_year_ahead")

        languages = fields.get("preferred-languages", [])
        if len(languages) > 1:
            errors.append("multiple_preferred_languages")
        elif languages:
            tags = [tag.strip() for tag in languages[0].split(",")]
            invalid_tags = [tag for tag in tags if not valid_language_tag(tag)]
            if not tags or invalid_tags:
                detail = ", ".join(invalid_tags) if invalid_tags else "empty"
                errors.append(f"invalid_preferred_languages:{detail}")

        for field_name in URI_FIELDS:
            for index, value in enumerate(fields.get(field_name, []), start=1):
                if (
                    field_name == "contact"
                    and "@" in value
                    and not URI_SCHEME_RE.match(value)
                ):
                    errors.append(f"contact_missing_mailto:{index}")
                    continue
                uri_error = validate_uri(value)
                if uri_error:
                    errors.append(f"invalid_uri:{field_name}:{index}:{uri_error}")
                    continue
                scheme = urlsplit(value).scheme.lower()
                if scheme == "http":
                    errors.append(f"insecure_web_uri:{field_name}:{index}")
                suffix = unregistered_well_known_suffix(value)
                if suffix:
                    errors.append(
                        f"unregistered_well_known_uri:{field_name}:{index}:{suffix}"
                    )

        canonicals = fields.get("canonical", [])
        valid_canonicals = [
            value for value in canonicals if validate_uri(value) is None
        ]
        retrieval_uris = {
            comparable
            for value in (requested_url, final_url)
            if (comparable := comparable_web_uri(value)) is not None
        }
        if valid_canonicals and not any(
            comparable_web_uri(value) in retrieval_uris for value in valid_canonicals
        ):
            warnings.append("canonical_does_not_match_retrieval_url")

    # Preserve order but avoid duplicate aggregate error labels.
    errors = list(dict.fromkeys(errors))
    warnings = list(dict.fromkeys(warnings))
    extension_fields = list(dict.fromkeys(extension_fields))
    registered_extension_fields = list(dict.fromkeys(registered_extension_fields))
    unknown_fields = list(dict.fromkeys(unknown_fields))
    duplicate_fields = sorted(
        name for name, values in fields.items() if len(values) > 1
    )

    return {
        "rfc9116_valid": not errors,
        "validation_errors": errors,
        "validation_warnings": warnings,
        "validation_info": info,
        "utf8_valid": utf8_valid,
        "media_type": media_type,
        "charset": charset,
        "signed": signed,
        "expires_at": expires_at,
        "expired": expired,
        "fields": fields,
        "extension_fields": extension_fields,
        "registered_extension_fields": registered_extension_fields,
        "unknown_fields": unknown_fields,
        "duplicate_fields": duplicate_fields,
        "body_text": text if utf8_valid else None,
        "body_base64": None if utf8_valid else base64.b64encode(body).decode("ascii"),
    }


def looks_like_html(body: bytes) -> bool:
    """Recognize common HTML response prefixes."""
    prefix = body[:4096].lstrip()
    if prefix.startswith(b"\xef\xbb\xbf"):
        prefix = prefix[3:].lstrip()
    prefix = prefix.lower()
    html_markers = (
        b"<!doctype html",
        b"<html",
        b"<head",
        b"<body",
        b"<title",
        b"<meta",
        b"<script",
    )
    return prefix.startswith(html_markers)


def looks_like_security_txt(body: bytes) -> bool:
    """Recognize a likely attempted security.txt despite a wrong MIME type."""
    prefix = body[:32_768]
    return bool(
        re.search(
            rb"(?im)^[ \t]*[\"']?(?:contact|expires):[ \t]",
            prefix,
        )
    )
