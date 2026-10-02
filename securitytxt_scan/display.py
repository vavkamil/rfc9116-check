"""Human-readable summaries and live progress output."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .findings import INFO_LABELS, ISSUE_LABELS, ISSUE_PRIORITY, WARNING_LABELS
from .summary import percentage


def format_ratio(numerator: int, denominator: int, suffix: str = "") -> str:
    """Format a count, denominator, and percentage for terminal output."""
    percent = percentage(numerator, denominator)
    percent_text = "N/A" if percent is None else f"{percent:.2f}%"
    suffix_text = f" {suffix}" if suffix else ""
    return f"{numerator}/{denominator}{suffix_text} ({percent_text})"


def format_short_summary(summary: dict[str, Any]) -> str:
    """Render headline statistics and findings as plain text."""
    total = summary["total_domains"]
    present = summary["security_txt_present"]
    valid = summary["rfc9116_valid"]
    invalid = summary["rfc9116_invalid_present"]
    absent = summary["security_txt_absent"]
    classifications = summary.get("classification_counts", {})
    blocked = classifications.get("blocked", 0)
    unreachable = classifications.get("unreachable", 0)
    inconclusive = classifications.get(
        "inconclusive", total - present - absent - blocked - unreachable
    )
    lines = [
        "Summary",
        f"  Domains:             {total}",
        f"  DNS resolved:        {format_ratio(summary['dns_resolved'], total)}",
        f"  security.txt found:  {format_ratio(present, total)}",
        f"  RFC 9116 valid:      {format_ratio(valid, present, 'found')}",
        f"  RFC 9116 invalid:    {format_ratio(invalid, present, 'found')}",
        f"  Absent / fallback:   {format_ratio(absent, total)}",
        f"  Blocked (HTTP 403):  {format_ratio(blocked, total)}",
        f"  Unreachable:         {format_ratio(unreachable, total)}",
        f"  Other inconclusive:  {format_ratio(inconclusive, total)}",
    ]

    findings = summary.get("validation_findings", [])
    if findings:
        label_width = max(len("Finding"), *(len(item["label"]) for item in findings))
        count_width = max(
            len("Domains"), *(len(str(item["domains"])) for item in findings)
        )
        header = (
            f"  {'Finding':<{label_width}}  {'Kind':<7}  "
            f"{'Domains':>{count_width}}  {'% found':>8}"
        )
        lines.extend(
            [
                "",
                f"Validation findings ({present} found files)",
                header,
                "  " + "-" * (len(header) - 2),
            ]
        )
        for item in findings:
            percent = item["percent_of_found"]
            percent_text = "N/A" if percent is None else f"{percent:.2f}%"
            lines.append(
                f"  {item['label']:<{label_width}}  {item['severity']:<7}  "
                f"{item['domains']:>{count_width}}  {percent_text:>8}"
            )
    return "\n".join(lines)


def print_short_summary(summary: dict[str, Any]) -> None:
    """Print the human-readable summary."""
    print()
    print(format_short_summary(summary))


def shorten(value: str, width: int) -> str:
    """Truncate a string to a fixed display width."""
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def human_duration(seconds: float) -> str:
    """Return a compact, approximate duration using at most two units."""
    remaining = max(0, int(abs(seconds)))
    days, remainder = divmod(remaining, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes = remainder // 60
    years, days = divmod(days, 365)
    months, days = divmod(days, 30)
    parts: list[str] = []
    for amount, suffix in (
        (years, "y"),
        (months, "mo"),
        (days, "d"),
        (hours, "h"),
        (minutes, "m"),
    ):
        if amount:
            parts.append(f"{amount}{suffix}")
        if len(parts) == 2:
            break
    return " ".join(parts) if parts else "<1m"


def expiry_distance(result: dict[str, Any]) -> tuple[str, bool] | None:
    """Return the approximate distance and direction of a file's expiry."""
    expires_at = result.get("expires_at")
    scanned_at = result.get("scanned_at")
    if not expires_at or not scanned_at:
        return None
    try:
        expires = datetime.fromisoformat(str(expires_at))
        scanned = datetime.fromisoformat(str(scanned_at))
        seconds = (expires - scanned).total_seconds()
    except (TypeError, ValueError):
        return None
    return human_duration(seconds), seconds >= 0


def issue_label(error: str, result: dict[str, Any]) -> str:
    """Convert a detailed validation error into a concise display label."""
    parts = error.split(":")
    code = parts[0]
    label = ISSUE_LABELS.get(code, error)
    if code == "expired":
        distance = expiry_distance(result)
        if distance:
            duration, _ = distance
            return f"expired ({duration} ago)"
    if code == "invalid_uri" and len(parts) >= 2:
        field_name = parts[1]
        detail = ""
        if parts[-1] == "contains whitespace or a control character":
            detail = " (whitespace)"
        return f"{field_name} URI{detail}"
    if code == "insecure_web_uri" and len(parts) >= 2:
        return f"insecure {parts[1]} URI"
    if code == "invalid_preferred_languages" and len(parts) >= 2:
        return f"invalid language tag ({parts[1]})"
    return label


def warning_label(warning: str, result: dict[str, Any]) -> str:
    """Convert a warning code into a concise display label."""
    label = WARNING_LABELS.get(warning, warning)
    if warning == "expires_more_than_one_year_ahead":
        distance = expiry_distance(result)
        if distance:
            duration, ahead = distance
            direction = "ahead" if ahead else "ago"
            return f"long expiry ({duration} {direction})"
    return label


def progress_details(result: dict[str, Any]) -> str:
    """Choose the most useful validation details for a progress row."""
    errors = result.get("validation_errors", [])
    warnings = result.get("validation_warnings", [])
    info = result.get("validation_info", [])
    if errors:
        ordered_errors = sorted(
            errors,
            key=lambda error: ISSUE_PRIORITY.get(error.split(":", 1)[0], 50),
        )
        labels = list(
            dict.fromkeys(issue_label(error, result) for error in ordered_errors)
        )
        shown = ", ".join(labels[:3])
        if len(labels) > 3:
            shown += f" (+{len(labels) - 3})"
        return shown
    if warnings:
        labels = list(
            dict.fromkeys(warning_label(warning, result) for warning in warnings)
        )
        shown = ", ".join(labels[:3])
        if len(labels) > 3:
            shown += f" (+{len(labels) - 3})"
        return "note: " + shown
    if info:
        labels = list(dict.fromkeys(INFO_LABELS.get(code, code) for code in info))
        shown = ", ".join(labels[:3])
        if len(labels) > 3:
            shown += f" (+{len(labels) - 3})"
        return "info: " + shown
    # Keep routine absent/inconclusive diagnostics in JSON and CSV without
    # cluttering the live table. A 403 is worth retaining as a likely WAF case.
    if (
        result.get("presence") == "http_inconclusive"
        and result.get("http_status") == 403
    ):
        return "possible WAF"
    return ""


def format_progress_row(
    result: dict[str, Any], position: int, number_width: int, domain_width: int
) -> str:
    """Format one scan result as a fixed-width progress-table row."""
    presence_labels = {
        "present": "found",
        "absent": "absent",
        "absent_html": "absent",
        "absent_redirect_html": "absent",
        "absent_unexpected_content": "absent",
        "empty_response": "empty",
        "encoded_response": "inconclusive",
        "http_inconclusive": "inconclusive",
        "inconclusive": "inconclusive",
    }
    domain = shorten(str(result.get("domain", "-")), domain_width)
    http = str(result.get("http_status") or "N/A")
    presence = presence_labels.get(str(result.get("presence")), "unknown")
    if (
        result.get("presence") == "http_inconclusive"
        and result.get("http_status") == 403
    ):
        presence = "blocked"
    if result.get("security_txt_present"):
        rfc = "valid" if result.get("rfc9116_valid") else "invalid"
    else:
        rfc = "-"
    details = shorten(progress_details(result), 68)
    return (
        f"{position:>{number_width}}  "
        f"{domain:<{domain_width}}  "
        f"{http:>6}  {presence:<12}  {rfc:<7}  {details}"
    ).rstrip()


def print_progress_header(number_width: int, domain_width: int) -> None:
    """Print the progress-table heading."""
    header = (
        f"{'#':>{number_width}}  {'Domain':<{domain_width}}  "
        f"{'HTTP':>6}  {'security.txt':<12}  {'RFC':<7}  Issue / note"
    )
    print()
    print(header)
    print("-" * len(header))
