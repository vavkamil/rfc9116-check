"""Atomic result persistence, CSV export, and checkpoints."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def atomic_write_json(path: Path, value: Any) -> None:
    """Atomically write a pretty-printed JSON value."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(path)


def atomic_write_jsonl(path: Path, values: Iterable[dict[str, Any]]) -> None:
    """Atomically write result objects in JSON Lines format."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for value in values:
            handle.write(
                json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
    temporary.replace(path)


def atomic_write_text(path: Path, value: str) -> None:
    """Atomically write UTF-8 text with LF line endings."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(value)
    temporary.replace(path)


CSV_COLUMNS = [
    "domain",
    "dns_resolved",
    "ip_addresses",
    "http_responded",
    "http_status",
    "presence",
    "classification",
    "flags",
    "security_txt_present",
    "rfc9116_valid",
    "final_url",
    "redirect_count",
    "content_type_header",
    "content_encoding_header",
    "media_type",
    "charset",
    "body_bytes",
    "body_sha256",
    "utf8_valid",
    "expires_at",
    "expired",
    "signed",
    "contacts",
    "preferred_languages",
    "extension_fields",
    "registered_extension_fields",
    "unknown_fields",
    "duplicate_fields",
    "validation_errors",
    "error_codes",
    "validation_warnings",
    "warning_codes",
    "validation_info",
    "info_codes",
    "transport_error",
    "transport_error_detail",
    "elapsed_ms",
    "scanned_at",
]


def csv_row(result: dict[str, Any]) -> dict[str, Any]:
    """Flatten one detailed result into the published CSV schema."""
    fields = result.get("fields") or {}

    def packed(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    return {
        "domain": result.get("domain"),
        "dns_resolved": result.get("dns_resolved"),
        "ip_addresses": packed(result.get("ip_addresses", [])),
        "http_responded": result.get("http_responded"),
        "http_status": result.get("http_status"),
        "presence": result.get("presence"),
        "classification": result.get("classification"),
        "flags": packed(result.get("flags", [])),
        "security_txt_present": result.get("security_txt_present"),
        "rfc9116_valid": result.get("rfc9116_valid"),
        "final_url": result.get("final_url"),
        "redirect_count": len(result.get("redirects", [])),
        "content_type_header": result.get("content_type_header"),
        "content_encoding_header": result.get("content_encoding_header"),
        "media_type": result.get("media_type"),
        "charset": result.get("charset"),
        "body_bytes": result.get("body_bytes"),
        "body_sha256": result.get("body_sha256"),
        "utf8_valid": result.get("utf8_valid"),
        "expires_at": result.get("expires_at"),
        "expired": result.get("expired"),
        "signed": result.get("signed"),
        "contacts": packed(fields.get("contact", [])),
        "preferred_languages": packed(fields.get("preferred-languages", [])),
        "extension_fields": packed(result.get("extension_fields", [])),
        "registered_extension_fields": packed(
            result.get("registered_extension_fields", [])
        ),
        "unknown_fields": packed(result.get("unknown_fields", [])),
        "duplicate_fields": packed(result.get("duplicate_fields", [])),
        "validation_errors": packed(result.get("validation_errors", [])),
        "error_codes": packed(result.get("error_codes", [])),
        "validation_warnings": packed(result.get("validation_warnings", [])),
        "warning_codes": packed(result.get("warning_codes", [])),
        "validation_info": packed(result.get("validation_info", [])),
        "info_codes": packed(result.get("info_codes", [])),
        "transport_error": result.get("transport_error"),
        "transport_error_detail": result.get("transport_error_detail"),
        "elapsed_ms": result.get("elapsed_ms"),
        "scanned_at": result.get("scanned_at"),
    }


def write_csv(path: Path, results: list[dict[str, Any]]) -> None:
    """Atomically write all results as CSV."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for result in results:
            writer.writerow(csv_row(result))
    temporary.replace(path)


def load_checkpoint(path: Path) -> dict[str, dict[str, Any]]:
    """Load the newest valid checkpoint record for each domain."""
    results: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return results
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"warning: ignoring incomplete checkpoint line {line_number}",
                    file=sys.stderr,
                )
                continue
            if item.get("domain"):
                results[item["domain"]] = item
    return results


def prepare_output(args: argparse.Namespace) -> tuple[Path, dict[str, dict[str, Any]]]:
    """Prepare output paths and optionally load resumable results."""
    output_dir: Path = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = output_dir / "results.jsonl"
    generated = [
        checkpoint,
        output_dir / "results.json",
        output_dir / "results.csv",
        output_dir / "summary.json",
        output_dir / "summary.txt",
    ]

    if args.overwrite:
        for path in generated:
            path.unlink(missing_ok=True)
        return checkpoint, {}
    if args.resume:
        return checkpoint, load_checkpoint(checkpoint)
    if any(path.exists() for path in generated):
        raise SystemExit(
            f"output already exists in {output_dir}; use --resume or --overwrite"
        )
    return checkpoint, {}
