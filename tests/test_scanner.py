import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from securitytxt_scan.findings import annotate_result
from securitytxt_scan.scanner import (
    RateLimiter,
    TooManyRedirects,
    UnsafeRedirect,
    redirect_leaves_original_domain,
    scan_domain,
)
from securitytxt_scan.validation import looks_like_html, looks_like_security_txt

from .helpers import URL


class ScannerTests(unittest.TestCase):
    def test_off_domain_redirect_detection_ignores_www_subdomain(self):
        self.assertFalse(
            redirect_leaves_original_domain(
                URL,
                [{"to": "https://www.example.cz/.well-known/security.txt"}],
            )
        )
        self.assertTrue(
            redirect_leaves_original_domain(
                URL,
                [{"to": "https://security.vendor.test/security.txt"}],
            )
        )

    def test_response_body_sniffing_distinguishes_html_from_attempted_file(self):
        self.assertTrue(looks_like_html(b"\xef\xbb\xbf  <html><body>fallback"))
        self.assertTrue(looks_like_html(b'<meta name="robots" content="noindex">'))
        self.assertFalse(looks_like_html(b'  "Contact: mailto:security@example.cz"\n'))
        self.assertTrue(
            looks_like_security_txt(b'  "Contact: mailto:security@example.cz"\n')
        )
        self.assertFalse(looks_like_security_txt(b'{"error":"not found"}\n'))

    @staticmethod
    def response(
        body,
        content_type="text/plain; charset=utf-8",
        content_encoding="identity",
    ):
        response = Mock()
        response.status = 200
        response.headers = {
            "Content-Type": content_type,
            "Content-Encoding": content_encoding,
        }
        response.geturl.return_value = URL
        response.read.return_value = body
        return response

    @patch(
        "securitytxt_scan.scanner.resolve_host",
        return_value=(["93.184.216.34"], None),
    )
    @patch("securitytxt_scan.scanner.build_opener")
    def test_scan_domain_recognizes_valid_plain_text(self, build, _resolve):
        build.return_value.open.return_value = self.response(
            b"Contact: mailto:security@example.cz\nExpires: 2027-01-01T00:00:00Z\n"
        )
        result = scan_domain(
            "example.cz",
            timeout=1,
            user_agent="test",
            max_redirects=2,
            max_body_bytes=32_768,
            limiter=RateLimiter(0),
        )
        self.assertEqual("present", result["presence"])
        self.assertTrue(result["security_txt_present"])
        self.assertTrue(result["rfc9116_valid"])

    @patch(
        "securitytxt_scan.scanner.resolve_host",
        return_value=(["93.184.216.34"], None),
    )
    @patch("securitytxt_scan.scanner.build_opener")
    def test_misused_utf8_content_encoding_is_only_a_transport_warning(
        self, build, _resolve
    ):
        build.return_value.open.return_value = self.response(
            b"Contact: mailto:security@example.cz\nExpires: 2027-01-01T00:00:00Z\n",
            content_encoding="utf8",
        )
        result = scan_domain(
            "example.cz",
            timeout=1,
            user_agent="test",
            max_redirects=2,
            max_body_bytes=32_768,
            limiter=RateLimiter(0),
        )
        annotate_result(result)
        self.assertTrue(result["rfc9116_valid"])
        self.assertIn("invalid_content_encoding", result["warning_codes"])
        self.assertIn("invalid_content_encoding", result["flags"])

    @patch(
        "securitytxt_scan.scanner.resolve_host",
        return_value=(["93.184.216.34"], None),
    )
    @patch("securitytxt_scan.scanner.build_opener")
    def test_oversized_response_is_inconclusive_not_invalid(self, build, _resolve):
        build.return_value.open.return_value = self.response(b"x" * 11)
        result = scan_domain(
            "example.cz",
            timeout=1,
            user_agent="test",
            max_redirects=2,
            max_body_bytes=10,
            limiter=RateLimiter(0),
        )
        annotate_result(result)
        self.assertEqual("inconclusive", result["presence"])
        self.assertEqual("inconclusive", result["classification"])
        self.assertEqual("response_too_large", result["transport_error"])
        self.assertFalse(result["security_txt_present"])

    @patch(
        "securitytxt_scan.scanner.resolve_host",
        return_value=(["93.184.216.34"], None),
    )
    @patch("securitytxt_scan.scanner.build_opener")
    def test_oversized_html_response_is_an_absent_fallback(self, build, _resolve):
        build.return_value.open.return_value = self.response(
            b"<html>" + b"x" * 20,
            content_type="text/html; charset=utf-8",
        )
        result = scan_domain(
            "example.cz",
            timeout=1,
            user_agent="test",
            max_redirects=2,
            max_body_bytes=10,
            limiter=RateLimiter(0),
        )
        annotate_result(result)
        self.assertEqual("absent_html", result["presence"])
        self.assertEqual("absent", result["classification"])
        self.assertTrue(result["body_truncated"])
        self.assertIsNone(result["transport_error"])

    @patch(
        "securitytxt_scan.scanner.resolve_host",
        return_value=(["93.184.216.34"], None),
    )
    @patch("securitytxt_scan.scanner.build_opener")
    def test_redirect_failures_are_inconclusive_not_unreachable(self, build, _resolve):
        for exception in (
            TooManyRedirects("too many"),
            UnsafeRedirect("bad target"),
        ):
            with self.subTest(exception=exception):
                build.return_value.open.side_effect = exception
                result = scan_domain(
                    "example.cz",
                    timeout=1,
                    user_agent="test",
                    max_redirects=2,
                    max_body_bytes=32_768,
                    limiter=RateLimiter(0),
                )
                annotate_result(result)
                self.assertTrue(result["http_responded"])
                self.assertEqual("inconclusive", result["classification"])

    @patch(
        "securitytxt_scan.scanner.resolve_host",
        return_value=(["93.184.216.34"], None),
    )
    @patch("securitytxt_scan.scanner.build_opener")
    def test_scan_domain_keeps_http_403_inconclusive(self, build, _resolve):
        build.return_value.open.side_effect = HTTPError(URL, 403, "Forbidden", {}, None)
        result = scan_domain(
            "example.cz",
            timeout=1,
            user_agent="test",
            max_redirects=2,
            max_body_bytes=32_768,
            limiter=RateLimiter(0),
        )
        annotate_result(result)
        self.assertEqual("http_inconclusive", result["presence"])
        self.assertEqual("blocked", result["classification"])
