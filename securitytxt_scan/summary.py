"""Aggregate statistics and validation-finding summaries."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from . import WELL_KNOWN_PATH
from . import __version__ as VERSION
from .findings import (
    CHARSET_ERROR_CODES,
    FINDING_LABELS,
    ISSUE_LABELS,
    MIME_ERROR_CODES,
    SYNTAX_ERROR_CODES,
    WARNING_FLAG_ALIASES,
)
from .validation import (
    IANA_SECURITY_TXT_FIELDS_REGISTRY_DATE,
    IANA_SECURITY_TXT_FIELDS_REGISTRY_URL,
)
from .well_known import IANA_WELL_KNOWN_REGISTRY_DATE, IANA_WELL_KNOWN_REGISTRY_URL


def percentage(numerator: int, denominator: int) -> float | None:
    """Return a percentage rounded to two places, or None for zero totals."""
    if denominator == 0:
        return None
    return round(100 * numerator / denominator, 2)


def summarize_validation_findings(
    results: list[dict[str, Any]], present: int
) -> list[dict[str, Any]]:
    """Count affected domains once per concise validation finding."""
    counts: Counter[tuple[str, str]] = Counter()
    for item in results:
        if not item.get("security_txt_present"):
            continue
        per_domain: set[tuple[str, str]] = set()
        for code in item.get("error_codes", []):
            if code in CHARSET_ERROR_CODES:
                concise = "charset_error"
            elif code in MIME_ERROR_CODES:
                concise = "mime_error"
            elif code in SYNTAX_ERROR_CODES:
                concise = "syntax_error"
            else:
                concise = code
            per_domain.add(("error", concise))
        for code in item.get("warning_codes", []):
            concise = WARNING_FLAG_ALIASES.get(code, code)
            per_domain.add(("warning", concise))
        for code in item.get("info_codes", []):
            per_domain.add(("info", code))
        counts.update(per_domain)

    findings = []
    for (severity, code), count in counts.items():
        fallback = ISSUE_LABELS.get(code, code.replace("_", " "))
        label = FINDING_LABELS.get(code, fallback)
        findings.append(
            {
                "code": code,
                "label": label[0].upper() + label[1:] if label else code,
                "severity": severity,
                "domains": count,
                "percent_of_found": percentage(count, present),
            }
        )
    return sorted(
        findings,
        key=lambda item: (
            -item["domains"],
            {"error": 0, "warning": 1, "info": 2}.get(item["severity"], 3),
            item["label"],
        ),
    )


def make_summary(
    results: list[dict[str, Any]], args: argparse.Namespace
) -> dict[str, Any]:
    """Build the machine-readable aggregate summary for a completed scan."""
    total = len(results)
    resolved = sum(bool(item.get("dns_resolved")) for item in results)
    responded = sum(bool(item.get("http_responded")) for item in results)
    present = sum(bool(item.get("security_txt_present")) for item in results)
    valid = sum(bool(item.get("rfc9116_valid")) for item in results)

    presence_counts = Counter(item.get("presence", "unknown") for item in results)
    absent = sum(
        presence_counts.get(state, 0)
        for state in (
            "absent",
            "absent_html",
            "absent_redirect_html",
            "absent_unexpected_content",
        )
    )
    status_counts = Counter(
        str(item["http_status"])
        for item in results
        if item.get("http_status") is not None
    )
    transport_errors = Counter(
        item["transport_error"] for item in results if item.get("transport_error")
    )
    validation_errors = Counter(
        error.split(":", 1)[0]
        for item in results
        for error in item.get("validation_errors", [])
    )
    validation_warnings = Counter(
        warning for item in results for warning in item.get("validation_warnings", [])
    )
    validation_info = Counter(
        info for item in results for info in item.get("validation_info", [])
    )
    field_usage = Counter(
        field_name for item in results for field_name in (item.get("fields") or {})
    )
    classifications = Counter(item.get("classification", "unknown") for item in results)
    flags = Counter(flag for item in results for flag in item.get("flags", []))

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanner_version": VERSION,
        "input": str(args.input),
        "requested_path": WELL_KNOWN_PATH,
        "well_known_uri_registry": {
            "snapshot_date": IANA_WELL_KNOWN_REGISTRY_DATE,
            "source": IANA_WELL_KNOWN_REGISTRY_URL,
        },
        "security_txt_fields_registry": {
            "snapshot_date": IANA_SECURITY_TXT_FIELDS_REGISTRY_DATE,
            "source": IANA_SECURITY_TXT_FIELDS_REGISTRY_URL,
        },
        "total_domains": total,
        "dns_resolved": resolved,
        "dns_failed": total - resolved,
        "http_responded": responded,
        "security_txt_present": present,
        "security_txt_absent": absent,
        "rfc9116_valid": valid,
        "rfc9116_invalid_present": present - valid,
        "rates_percent": {
            "dns_resolved_of_total": percentage(resolved, total),
            "present_of_total": percentage(present, total),
            "present_of_dns_resolved": percentage(present, resolved),
            "valid_of_total": percentage(valid, total),
            "valid_of_present": percentage(valid, present),
        },
        "presence_counts": dict(sorted(presence_counts.items())),
        "classification_counts": dict(sorted(classifications.items())),
        "flag_counts": dict(sorted(flags.items())),
        "validation_findings": summarize_validation_findings(results, present),
        "http_status_counts": dict(sorted(status_counts.items())),
        "transport_error_counts": dict(sorted(transport_errors.items())),
        "validation_error_counts": dict(sorted(validation_errors.items())),
        "validation_warning_counts": dict(sorted(validation_warnings.items())),
        "validation_info_counts": dict(sorted(validation_info.items())),
        "field_usage_counts": dict(sorted(field_usage.items())),
        "settings": {
            "timeout_seconds": args.timeout,
            "workers": args.workers,
            "delay_between_request_starts_seconds": args.delay,
            "max_redirects": args.max_redirects,
            "max_body_bytes": args.max_body_bytes,
            "user_agent": args.user_agent,
        },
    }
