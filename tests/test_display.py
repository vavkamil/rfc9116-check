import unittest

from securitytxt_scan.display import (
    format_progress_row,
    format_ratio,
    format_short_summary,
    human_duration,
    progress_details,
)


class DisplayTests(unittest.TestCase):
    def test_summary_ratio_formatting(self):
        self.assertEqual("38/160 found (23.75%)", format_ratio(38, 160, "found"))
        self.assertEqual("0/0 found (N/A)", format_ratio(0, 0, "found"))

    def test_progress_row_shows_status_and_validation_problem(self):
        row = format_progress_row(
            {
                "domain": "google.cz",
                "dns_resolved": True,
                "http_status": 200,
                "presence": "present",
                "security_txt_present": True,
                "rfc9116_valid": False,
                "validation_errors": ["missing_expires"],
            },
            position=6,
            number_width=2,
            domain_width=18,
        )
        self.assertIn("google.cz", row)
        self.assertIn("found", row)
        self.assertIn("invalid", row)
        self.assertIn("expiry", row)

    def test_progress_row_keeps_waf_but_suppresses_html_redirect_note(self):
        blocked = format_progress_row(
            {
                "domain": "blocked.cz",
                "dns_resolved": True,
                "http_status": 403,
                "presence": "http_inconclusive",
            },
            position=1,
            number_width=1,
            domain_width=18,
        )
        redirected = format_progress_row(
            {
                "domain": "redirected.cz",
                "dns_resolved": True,
                "http_status": 200,
                "presence": "absent_redirect_html",
            },
            position=2,
            number_width=1,
            domain_width=18,
        )
        self.assertIn("blocked", blocked)
        self.assertIn("possible WAF", blocked)
        self.assertIn("absent", redirected)
        self.assertNotIn("HTML page", redirected)

    def test_expiry_notes_include_relative_duration(self):
        expired = progress_details(
            {
                "validation_errors": ["expired"],
                "validation_warnings": [],
                "expires_at": "2025-01-01T00:00:00+00:00",
                "scanned_at": "2026-10-01T00:00:00+00:00",
            }
        )
        long_expiry = progress_details(
            {
                "validation_errors": [],
                "validation_warnings": ["expires_more_than_one_year_ahead"],
                "expires_at": "2030-07-01T00:00:00+00:00",
                "scanned_at": "2026-10-01T00:00:00+00:00",
            }
        )
        self.assertEqual("expired (1y 9mo ago)", expired)
        self.assertEqual("note: long expiry (3y 9mo ahead)", long_expiry)
        self.assertEqual("2d 3h", human_duration(2 * 86_400 + 3 * 3_600))

    def test_unknown_content_encoding_is_inconclusive_not_empty(self):
        row = format_progress_row(
            {
                "domain": "encoded.cz",
                "dns_resolved": True,
                "http_status": 200,
                "presence": "encoded_response",
                "transport_error": "unsupported_content_encoding",
                "transport_error_detail": "br",
            },
            position=1,
            number_width=1,
            domain_width=18,
        )
        self.assertIn("inconclusive", row)
        self.assertNotIn("unsupported encoding", row)

    def test_progress_prioritizes_required_fields_and_names_uri_field(self):
        details = progress_details(
            {
                "validation_errors": [
                    "missing_utf8_charset",
                    "missing_final_line_separator",
                    "missing_expires",
                    "invalid_uri:policy:1:not an absolute URI",
                ],
                "validation_warnings": [],
            }
        )
        self.assertEqual("no expiry, policy URI, charset header (+1)", details)

    def test_human_summary_is_suitable_for_text_output(self):
        summary = {
            "total_domains": 10,
            "dns_resolved": 10,
            "security_txt_present": 5,
            "security_txt_absent": 4,
            "rfc9116_valid": 2,
            "rfc9116_invalid_present": 3,
            "classification_counts": {
                "blocked": 1,
                "unreachable": 0,
                "inconclusive": 0,
            },
            "validation_findings": [
                {
                    "label": "Charset header",
                    "severity": "error",
                    "domains": 3,
                    "percent_of_found": 60.0,
                }
            ],
        }
        text = format_short_summary(summary)
        self.assertTrue(text.startswith("Summary\n"))
        self.assertIn("security.txt found:  5/10 (50.00%)", text)
        self.assertIn("Validation findings (5 found files)", text)
        self.assertIn("Charset header", text)
        self.assertFalse(text.endswith("\n"))
