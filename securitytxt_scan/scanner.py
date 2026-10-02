"""DNS, HTTP, TLS, redirect, and per-domain scanning."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import WELL_KNOWN_PATH
from .validation import (
    looks_like_html,
    looks_like_security_txt,
    parse_content_type,
    validate_security_txt,
)


class TooManyRedirects(Exception):
    """Indicate that a response exceeded the configured redirect limit."""


class UnsafeRedirect(Exception):
    """Indicate that a redirect target is unsupported or unsafe to request."""


class RateLimiter:
    """Ensure request starts are separated by at least ``delay`` seconds."""

    def __init__(self, delay: float) -> None:
        """Initialize a limiter with the minimum delay between starts."""
        self.delay = max(0.0, delay)
        self._lock = threading.Lock()
        self._next_start = 0.0

    def wait(self) -> None:
        """Block until the next request may start."""
        if not self.delay:
            return
        with self._lock:
            now = time.monotonic()
            wait_for = self._next_start - now
            if wait_for > 0:
                time.sleep(wait_for)
            self._next_start = time.monotonic() + self.delay


def resolve_host(host: str, port: int = 443) -> tuple[list[str], str | None]:
    """Resolve a hostname, returning sorted addresses and an optional error."""
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return [], f"{exc.__class__.__name__}: {exc}"
    except OSError as exc:
        return [], f"{exc.__class__.__name__}: {exc}"

    addresses = sorted({str(record[4][0]) for record in records})
    return addresses, None


def non_public_addresses(addresses: Iterable[str]) -> list[str]:
    """Return addresses that are not globally routable."""
    result = []
    for address in addresses:
        try:
            if not ipaddress.ip_address(address).is_global:
                result.append(address)
        except ValueError:
            result.append(address)
    return result


def redirect_leaves_original_domain(
    requested_url: str, redirects: Iterable[dict[str, Any]]
) -> bool:
    """Report whether a redirect leaves the original host and its subdomains."""
    original_host = (urlsplit(requested_url).hostname or "").lower().rstrip(".")
    if not original_host:
        return False
    for redirect in redirects:
        target_host = (urlsplit(str(redirect.get("to", ""))).hostname or "").lower()
        target_host = target_host.rstrip(".")
        if target_host != original_host and not target_host.endswith(
            "." + original_host
        ):
            return True
    return False


class SafeRedirectHandler(HTTPRedirectHandler):
    """Record redirects and refuse targets resolving to non-public addresses."""

    def __init__(self, max_redirects: int) -> None:
        """Initialize the handler with a maximum redirect count."""
        super().__init__()
        self.max_redirects = max_redirects
        self.history: list[dict[str, Any]] = []

    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        """Validate and record a redirect before delegating to urllib."""
        target = urljoin(req.full_url, newurl)
        if len(self.history) >= self.max_redirects:
            raise TooManyRedirects(f"more than {self.max_redirects} redirects")

        parsed = urlsplit(target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise UnsafeRedirect(f"unsupported redirect target: {target}")

        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addresses, error = resolve_host(parsed.hostname, port)
        unsafe = non_public_addresses(addresses)
        if error or not addresses:
            raise UnsafeRedirect(f"redirect target did not resolve: {target}")
        if unsafe:
            raise UnsafeRedirect(
                f"redirect target has non-public address(es): {', '.join(unsafe)}"
            )

        self.history.append({"status": int(code), "from": req.full_url, "to": target})
        return super().redirect_request(req, fp, code, msg, headers, target)


def classify_url_error(exc: Exception) -> str:
    """Map urllib and socket exceptions to stable transport-error codes."""
    reason = exc.reason if isinstance(exc, URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "tls_certificate_error"
    if isinstance(reason, ssl.SSLError):
        return "tls_error"
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(reason, ConnectionRefusedError):
        return "connection_refused"
    return "connection_error"


def scan_domain(
    domain: str,
    *,
    timeout: float,
    user_agent: str,
    max_redirects: int,
    max_body_bytes: int,
    limiter: RateLimiter,
) -> dict[str, Any]:
    """Retrieve and validate the well-known security.txt for one domain."""
    started = time.monotonic()
    requested_url = f"https://{domain}{WELL_KNOWN_PATH}"
    result: dict[str, Any] = {
        "domain": domain,
        "requested_url": requested_url,
        "dns_resolved": False,
        "ip_addresses": [],
        "non_public_addresses": [],
        "http_responded": False,
        "http_status": None,
        "final_url": None,
        "redirects": [],
        "content_type_header": None,
        "content_encoding_header": None,
        "content_length_header": None,
        "server_header": None,
        "body_bytes": 0,
        "body_sha256": None,
        "body_truncated": False,
        "presence": "inconclusive",
        "security_txt_present": False,
        "rfc9116_valid": False,
        "transport_error": None,
        "transport_error_detail": None,
        "elapsed_ms": None,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }

    addresses, dns_error = resolve_host(domain, 443)
    result["ip_addresses"] = addresses
    if dns_error or not addresses:
        result["transport_error"] = "dns_error"
        result["transport_error_detail"] = dns_error or "no addresses returned"
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        return result

    result["dns_resolved"] = True
    unsafe = non_public_addresses(addresses)
    result["non_public_addresses"] = unsafe
    if unsafe:
        result["transport_error"] = "non_public_address"
        result["transport_error_detail"] = ", ".join(unsafe)
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
        return result

    redirect_handler = SafeRedirectHandler(max_redirects=max_redirects)
    opener = build_opener(redirect_handler)
    request = Request(
        requested_url,
        headers={
            "User-Agent": user_agent,
            "Accept": "text/plain, */*;q=0.1",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )

    response = None
    body = b""
    invalid_content_encoding: str | None = None
    try:
        limiter.wait()
        response = opener.open(request, timeout=timeout)
        result["http_responded"] = True
        result["http_status"] = int(response.status)
        result["final_url"] = response.geturl()
        result["content_type_header"] = response.headers.get("Content-Type")
        result["content_encoding_header"] = response.headers.get("Content-Encoding")
        result["content_length_header"] = response.headers.get("Content-Length")
        result["server_header"] = response.headers.get("Server")
        content_encoding = (
            response.headers.get("Content-Encoding") or "identity"
        ).lower()
        if content_encoding in {"", "identity"}:
            body = response.read(max_body_bytes + 1)
        elif content_encoding in {"utf8", "utf-8"}:
            # A recurring server mistake: UTF-8 is a charset, not an HTTP
            # content-coding. The bytes are still an identity representation.
            invalid_content_encoding = content_encoding
            body = response.read(max_body_bytes + 1)
        else:
            result["transport_error"] = "unsupported_content_encoding"
            result["transport_error_detail"] = content_encoding
    except HTTPError as exc:
        result["http_responded"] = True
        result["http_status"] = int(exc.code)
        result["final_url"] = str(exc.url)
        result["content_type_header"] = exc.headers.get("Content-Type")
        result["content_encoding_header"] = exc.headers.get("Content-Encoding")
        result["content_length_header"] = exc.headers.get("Content-Length")
        result["server_header"] = exc.headers.get("Server")
        exc.close()
    except TooManyRedirects as exc:
        result["http_responded"] = True
        result["transport_error"] = "too_many_redirects"
        result["transport_error_detail"] = str(exc)
    except UnsafeRedirect as exc:
        result["http_responded"] = True
        result["transport_error"] = "unsafe_redirect"
        result["transport_error_detail"] = str(exc)
    except (URLError, OSError, TimeoutError) as exc:
        result["transport_error"] = classify_url_error(exc)
        result["transport_error_detail"] = f"{exc.__class__.__name__}: {exc}"
    finally:
        if response is not None:
            response.close()

    result["redirects"] = redirect_handler.history
    status = result["http_status"]
    if len(body) > max_body_bytes:
        body = body[:max_body_bytes]
        result["body_truncated"] = True
    result["body_bytes"] = len(body)
    if body:
        result["body_sha256"] = hashlib.sha256(body).hexdigest()

    if isinstance(status, int) and 200 <= status < 300:
        media_type, _ = parse_content_type(result["content_type_header"])
        if result["transport_error"] == "unsupported_content_encoding":
            result["presence"] = "encoded_response"
        elif not body:
            result["presence"] = "empty_response"
        elif looks_like_html(body):
            result["presence"] = (
                "absent_redirect_html" if result["redirects"] else "absent_html"
            )
        elif media_type != "text/plain" and not looks_like_security_txt(body):
            result["presence"] = "absent_unexpected_content"
        elif result["body_truncated"]:
            # A recognizable fallback can be classified from its prefix. An
            # attempted security.txt must be complete before it is validated.
            result["presence"] = "inconclusive"
            result["transport_error"] = "response_too_large"
            result["transport_error_detail"] = (
                f"response exceeded {max_body_bytes} bytes"
            )
        else:
            result["presence"] = "present"
            result["security_txt_present"] = True
            representation_errors: list[str] = []
            if any(
                urlsplit(redirect["to"]).scheme.lower() == "http"
                for redirect in result["redirects"]
            ):
                representation_errors.append("insecure_redirect")
            validation = validate_security_txt(
                body,
                result["content_type_header"],
                requested_url,
                result["final_url"] or requested_url,
                extra_errors=representation_errors,
            )
            result.update(validation)
            if invalid_content_encoding:
                result["validation_warnings"].append("invalid_content_encoding")
            if redirect_leaves_original_domain(requested_url, result["redirects"]):
                result["validation_warnings"].append("redirected_off_domain")
    elif status in {404, 410}:
        result["presence"] = "absent"
    elif status is not None:
        result["presence"] = "http_inconclusive"

    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result
