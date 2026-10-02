# rfc9116-check

A standard-library-only Python scanner for
[`security.txt`](https://www.rfc-editor.org/rfc/rfc9116.html). It requests
`https://<domain>/.well-known/security.txt` and checks the response against
RFC 9116.

The accompanying [blog post](https://vavkamil.cz/blog/2026-10-02-security-txt-on-czech-web/)
discusses the scan of popular `.cz` domains.

The input contains one domain per line. Blank lines, comments beginning with
`#`, and duplicate domains are ignored. Python 3.10 or newer is required.

## Usage

Scan the first 20 domains in the included list:

```bash
python scan_security_txt.py tranco-cz-top-1000.txt --limit 20
```

Run a fresh scan of the complete list, replacing the included results:

```bash
python scan_security_txt.py tranco-cz-top-1000.txt --overwrite
```

To continue an interrupted scan or reuse its existing checkpoint:

```bash
python scan_security_txt.py tranco-cz-top-1000.txt --resume
```

Results are written to `results-tranco-cz-top-1000/`, or
`results-tranco-cz-top-1000-first-20/` when the limit above is used. You can
also provide your own one-domain-per-line input file; the output directory is
derived from its filename.

Network settings such as the timeout, request delay, worker count, and user
agent are in the `CONFIG` mapping in `securitytxt_scan/cli.py`. The defaults
use one worker and a 200 ms delay between requests.

## Results

Each output directory contains:

- `results.json` with complete structured results
- `results.csv` for spreadsheets and charts
- `results.jsonl` as a resumable checkpoint
- `summary.json` with aggregate statistics
- `summary.txt` with the command-line summary

Every result has a `classification` of `valid`, `invalid`, `absent`, `blocked`,
`unreachable`, or `inconclusive`. Normalized `error_codes`, `warning_codes`,
`info_codes`, and `flags` make the JSON easy to query:

```bash
jq -r '.[] | select(.flags | index("expired")) | .domain' results-tranco-cz-top-1000/results.json
jq -r '.[] | select(.classification == "blocked") | .domain' results-tranco-cz-top-1000/results.json
jq -r '.[] | select(.flags | index("extension_fields")) |
  [.domain, (.extension_fields | join(", "))] | @tsv' results-tranco-cz-top-1000/results.json
```

The validator covers the practical RFC 9116 requirements, including HTTPS,
media type and UTF-8 handling, field syntax, `Contact`, `Expires`, URI fields,
line endings, language tags, and referenced well-known URIs. The relevant
IANA registry snapshots are pinned for reproducible results.
Recommendations such as an expiry more than one year away, non-NFC Unicode,
or a mismatched `Canonical` field are reported as warnings.

## Development

The scanner and its tests have no third-party runtime dependencies:

```bash
python -m unittest discover -v
```

Ruff and ty are available through the development dependency group:

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run ty check
```
