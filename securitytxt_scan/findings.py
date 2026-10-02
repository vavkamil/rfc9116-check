"""Finding codes, labels, and normalized result annotations."""

from __future__ import annotations

from typing import Any

ISSUE_LABELS = {
    "missing_content_type": "MIME missing",
    "content_type_not_text_plain": "MIME",
    "missing_utf8_charset": "charset header",
    "charset_not_utf8": "charset header",
    "final_url_not_https": "HTTPS",
    "insecure_redirect": "HTTP redirect",
    "empty_body": "empty",
    "invalid_utf8": "UTF-8",
    "utf8_bom_before_first_line": "BOM",
    "unassigned_unicode_code_point": "unassigned Unicode",
    "invalid_line_separator": "line endings",
    "missing_final_line_separator": "no final newline",
    "disallowed_control_character": "control chars",
    "invalid_pgp_cleartext_structure": "PGP syntax",
    "invalid_pgp_hash_header": "PGP hash",
    "invalid_pgp_signature_structure": "PGP signature",
    "content_after_pgp_signature": "PGP trailing data",
    "malformed_line": "syntax",
    "empty_field_value": "empty field",
    "missing_contact": "no contact",
    "missing_expires": "no expiry",
    "multiple_expires": "duplicate expiry",
    "invalid_expires_rfc3339": "expiry format",
    "expired": "expired",
    "multiple_preferred_languages": "duplicate languages",
    "invalid_preferred_languages": "invalid language tag",
    "invalid_uri": "URI",
    "contact_missing_mailto": "contact missing mailto",
    "insecure_web_uri": "insecure URI",
    "unregistered_well_known_uri": "unregistered well-known URI",
}

ISSUE_PRIORITY = {
    "missing_contact": 0,
    "missing_expires": 1,
    "expired": 2,
    "invalid_expires_rfc3339": 2,
    "multiple_expires": 2,
    "contact_missing_mailto": 3,
    "invalid_uri": 4,
    "insecure_web_uri": 4,
    "unregistered_well_known_uri": 4,
    "invalid_preferred_languages": 4,
    "multiple_preferred_languages": 4,
    "empty_field_value": 5,
    "malformed_line": 5,
    "invalid_utf8": 6,
    "unassigned_unicode_code_point": 6,
    "disallowed_control_character": 6,
    "content_after_pgp_signature": 6,
    "missing_content_type": 7,
    "content_type_not_text_plain": 7,
    "missing_utf8_charset": 7,
    "charset_not_utf8": 7,
    "final_url_not_https": 7,
    "insecure_redirect": 7,
    "missing_final_line_separator": 8,
}

WARNING_LABELS = {
    "expires_more_than_one_year_ahead": "long expiry",
    "canonical_does_not_match_retrieval_url": "canonical mismatch",
    "redirected_off_domain": "off-domain redirect",
    "not_unicode_nfc": "Unicode not NFC",
    "invalid_content_encoding": "invalid content encoding",
}

WARNING_FLAG_ALIASES = {
    "expires_more_than_one_year_ahead": "long_expiry",
    "canonical_does_not_match_retrieval_url": "canonical_mismatch",
    "redirected_off_domain": "off_domain_redirect",
    "not_unicode_nfc": "unicode_not_nfc",
}

INFO_LABELS = {"pgp_present": "PGP signature present"}

SYNTAX_ERROR_CODES = {
    "empty_field_value",
    "malformed_line",
    "invalid_pgp_cleartext_structure",
    "invalid_pgp_hash_header",
    "invalid_pgp_signature_structure",
    "content_after_pgp_signature",
}

CHARSET_ERROR_CODES = {"missing_utf8_charset", "charset_not_utf8"}
MIME_ERROR_CODES = {"missing_content_type", "content_type_not_text_plain"}
EXPIRY_ERROR_CODES = {
    "missing_expires",
    "multiple_expires",
    "invalid_expires_rfc3339",
    "expired",
}
URI_ERROR_CODES = {
    "invalid_uri",
    "contact_missing_mailto",
    "insecure_web_uri",
    "unregistered_well_known_uri",
}

FINDING_LABELS = {
    "charset_error": "Charset header",
    "mime_error": "MIME type",
    "syntax_error": "Syntax",
    "expiry_error": "Expiry",
    "uri_error": "URI/contact",
    "long_expiry": "Expiry over one year",
    "canonical_mismatch": "Canonical mismatch",
    "pgp_present": "PGP signature present",
    "off_domain_redirect": "Off-domain redirect",
    "unicode_not_nfc": "Unicode not NFC",
    "invalid_content_encoding": "Invalid content encoding",
}


def annotate_result(result: dict[str, Any]) -> dict[str, Any]:
    """Add stable, concise fields intended for jq and spreadsheet queries."""
    error_codes = list(
        dict.fromkeys(
            error.split(":", 1)[0] for error in result.get("validation_errors", [])
        )
    )
    legacy_pgp_code = "pgp_signature_not_cryptographically_verified"
    raw_warnings = list(result.get("validation_warnings", []))
    warning_codes = list(
        dict.fromkeys(code for code in raw_warnings if code != legacy_pgp_code)
    )
    info_codes = list(dict.fromkeys(result.get("validation_info", [])))
    if result.get("signed") or legacy_pgp_code in raw_warnings:
        info_codes = list(dict.fromkeys([*info_codes, "pgp_present"]))
    presence = result.get("presence")
    status = result.get("http_status")

    if result.get("security_txt_present"):
        classification = "valid" if result.get("rfc9116_valid") else "invalid"
    elif presence in {
        "absent",
        "absent_html",
        "absent_redirect_html",
        "absent_unexpected_content",
    }:
        classification = "absent"
    elif presence == "http_inconclusive" and status == 403:
        classification = "blocked"
    elif result.get("transport_error") and not result.get("http_responded"):
        classification = "unreachable"
    else:
        classification = "inconclusive"

    flags: list[str] = [classification]
    if result.get("security_txt_present"):
        flags.append("found")
        flags.append("rfc_valid" if result.get("rfc9116_valid") else "rfc_invalid")
    flags.extend(error_codes)
    flags.extend(WARNING_FLAG_ALIASES.get(code, code) for code in warning_codes)
    flags.extend(info_codes)

    transport_error = result.get("transport_error")
    if transport_error:
        flags.append(str(transport_error))
    if presence in {"absent_html", "absent_redirect_html"}:
        flags.append("html_fallback")
    elif presence == "absent_unexpected_content":
        flags.append("unexpected_content")
    if status == 401:
        flags.append("authentication_required")
    elif status == 403:
        flags.append("possible_waf")
    elif status == 429:
        flags.append("rate_limited")
    elif isinstance(status, int) and status >= 500:
        flags.append("server_error")
    if SYNTAX_ERROR_CODES.intersection(error_codes):
        flags.append("syntax_error")
    if CHARSET_ERROR_CODES.intersection(error_codes):
        flags.append("charset_error")
    if MIME_ERROR_CODES.intersection(error_codes):
        flags.append("mime_error")
    if EXPIRY_ERROR_CODES.intersection(error_codes):
        flags.append("expiry_error")
    if URI_ERROR_CODES.intersection(error_codes):
        flags.append("uri_error")
    if result.get("extension_fields"):
        flags.append("extension_fields")
    if result.get("registered_extension_fields"):
        flags.append("registered_extension_fields")
    if result.get("unknown_fields"):
        flags.append("unknown_fields")

    result["classification"] = classification
    result["error_codes"] = error_codes
    result["validation_warnings"] = warning_codes
    result["warning_codes"] = warning_codes
    result["validation_info"] = info_codes
    result["info_codes"] = info_codes
    result["flags"] = list(dict.fromkeys(flags))
    return result
