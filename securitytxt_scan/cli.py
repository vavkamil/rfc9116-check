"""Command-line interface and scan orchestration."""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__ as VERSION
from .display import (
    format_progress_row,
    format_short_summary,
    print_progress_header,
    print_short_summary,
)
from .findings import annotate_result
from .scanner import RateLimiter, scan_domain
from .storage import (
    atomic_write_json,
    atomic_write_jsonl,
    atomic_write_text,
    prepare_output,
    write_csv,
)
from .summary import make_summary

# Network and scanner settings that rarely need command-line overrides.
CONFIG: dict[str, Any] = {
    "timeout": 5.0,
    "workers": 1,
    "delay": 0.2,
    "max_redirects": 5,
    "max_body_bytes": 262_144,
    "user_agent": f"rfc9116-check/{VERSION} (personal research)",
    "progress_every": 1,
}


def read_domains(path: Path, limit: int | None = None) -> list[str]:
    """Read unique domains from a line-oriented input file."""
    domains: list[str] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            domain = line.lower().rstrip(".")

            if not domain or "," in domain or any(char.isspace() for char in domain):
                raise ValueError(f"{path}:{line_number}: invalid domain {domain!r}")
            if domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)
            if limit is not None and len(domains) >= limit:
                break

    return domains


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Scan domains for /.well-known/security.txt and validate RFC 9116",
    )
    parser.add_argument(
        "input",
        type=Path,
        help="domain list with one domain per line",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        help="scan only the first N domains; omit to scan the complete input",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument(
        "--resume", action="store_true", help="resume from results.jsonl"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing generated output files",
    )
    return parser


def apply_config(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Apply scanner settings and derive the output directory."""
    required = {
        "timeout",
        "workers",
        "delay",
        "max_redirects",
        "max_body_bytes",
        "user_agent",
        "progress_every",
    }
    missing = sorted(required - CONFIG.keys())
    if missing:
        parser.error(f"CONFIG is missing: {', '.join(missing)}")

    input_stem = args.input.stem or "domains"
    limit_suffix = f"-first-{args.limit}" if args.limit is not None else ""
    args.output_dir = Path(f"results-{input_stem}{limit_suffix}")
    args.timeout = float(CONFIG["timeout"])
    args.workers = int(CONFIG["workers"])
    args.delay = float(CONFIG["delay"])
    args.max_redirects = int(CONFIG["max_redirects"])
    args.max_body_bytes = int(CONFIG["max_body_bytes"])
    args.user_agent = str(CONFIG["user_agent"])
    args.progress_every = int(CONFIG["progress_every"])


def main(argv: list[str] | None = None) -> int:
    """Run the scanner command and return its process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    apply_config(args, parser)
    if args.limit is not None and args.limit <= 0:
        parser.error("limit must be positive")
    if args.workers <= 0:
        parser.error("CONFIG['workers'] must be positive")
    if args.timeout <= 0:
        parser.error("CONFIG['timeout'] must be positive")
    if args.delay < 0:
        parser.error("CONFIG['delay'] cannot be negative")
    if args.max_redirects < 0:
        parser.error("CONFIG['max_redirects'] cannot be negative")
    if args.max_body_bytes <= 0:
        parser.error("CONFIG['max_body_bytes'] must be positive")
    if args.progress_every <= 0:
        parser.error("CONFIG['progress_every'] must be positive")
    if args.resume and args.overwrite:
        parser.error("--resume and --overwrite are mutually exclusive")

    entries = read_domains(args.input, args.limit)
    if not entries:
        raise SystemExit("input did not contain any domains")
    checkpoint_path, completed = prepare_output(args)
    pending = [
        (position, domain)
        for position, domain in enumerate(entries, start=1)
        if domain not in completed
    ]
    limiter = RateLimiter(args.delay)

    print(
        f"Scanning {len(entries)} domains ({len(completed)} resumed, "
        f"{len(pending)} pending) with {args.workers} worker(s)."
    )
    print(f"Checkpoint: {checkpoint_path}")
    number_width = len(str(len(entries)))
    domain_width = min(40, max(18, *(len(domain) for domain in entries)))
    if pending:
        print_progress_header(number_width, domain_width)

    checkpoint_mode = "a" if completed else "w"
    with checkpoint_path.open(  # noqa: SIM117
        checkpoint_mode, encoding="utf-8"
    ) as checkpoint_handle:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map = {
                executor.submit(
                    scan_domain,
                    domain,
                    timeout=args.timeout,
                    user_agent=args.user_agent,
                    max_redirects=args.max_redirects,
                    max_body_bytes=args.max_body_bytes,
                    limiter=limiter,
                ): (position, domain)
                for position, domain in pending
            }
            newly_completed = 0
            try:
                for future in as_completed(future_map):
                    position, domain = future_map[future]
                    try:
                        result = future.result()
                    except Exception as exc:  # Keep a long scan resumable.
                        result = {
                            "domain": domain,
                            "dns_resolved": False,
                            "http_responded": False,
                            "presence": "inconclusive",
                            "security_txt_present": False,
                            "rfc9116_valid": False,
                            "transport_error": "internal_scanner_error",
                            "transport_error_detail": f"{exc.__class__.__name__}: {exc}",
                            "scanned_at": datetime.now(timezone.utc).isoformat(),
                        }
                    annotate_result(result)
                    completed[domain] = result
                    checkpoint_handle.write(
                        json.dumps(result, ensure_ascii=False, separators=(",", ":"))
                        + "\n"
                    )
                    checkpoint_handle.flush()
                    newly_completed += 1
                    done = len(completed)
                    if (
                        newly_completed == 1
                        or done == len(entries)
                        or done % args.progress_every == 0
                    ):
                        print(
                            format_progress_row(
                                result, position, number_width, domain_width
                            ),
                            flush=True,
                        )
            except KeyboardInterrupt:
                print("\nInterrupted; rerun with --resume.", file=sys.stderr)
                for future in future_map:
                    future.cancel()
                return 130

    # Also normalize records loaded from an older checkpoint.
    ordered_results = [annotate_result(completed[domain]) for domain in entries]
    results_json = args.output_dir / "results.json"
    results_csv = args.output_dir / "results.csv"
    summary_json = args.output_dir / "summary.json"
    summary_txt = args.output_dir / "summary.txt"
    atomic_write_jsonl(checkpoint_path, ordered_results)
    atomic_write_json(results_json, ordered_results)
    write_csv(results_csv, ordered_results)
    summary = make_summary(ordered_results, args)
    atomic_write_json(summary_json, summary)
    atomic_write_text(summary_txt, format_short_summary(summary) + "\n")

    print_short_summary(summary)
    print()
    print(f"Wrote {results_json}, {results_csv}, {summary_json}, and {summary_txt}")
    return 0
