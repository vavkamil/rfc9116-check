import unittest

from securitytxt_scan.findings import annotate_result
from securitytxt_scan.summary import summarize_validation_findings


class FindingTests(unittest.TestCase):
    def test_validation_findings_count_domains_and_group_charset(self):
        results = [
            annotate_result(
                {
                    "security_txt_present": True,
                    "rfc9116_valid": False,
                    "presence": "present",
                    "validation_errors": ["missing_utf8_charset"],
                    "validation_warnings": [],
                }
            ),
            annotate_result(
                {
                    "security_txt_present": True,
                    "rfc9116_valid": False,
                    "presence": "present",
                    "validation_errors": ["charset_not_utf8"],
                    "validation_warnings": ["expires_more_than_one_year_ahead"],
                }
            ),
        ]
        findings = {
            item["code"]: item for item in summarize_validation_findings(results, 2)
        }
        self.assertEqual(2, findings["charset_error"]["domains"])
        self.assertEqual(100.0, findings["charset_error"]["percent_of_found"])
        self.assertEqual(1, findings["long_expiry"]["domains"])

    def test_query_annotations_have_normalized_codes_and_flags(self):
        invalid = annotate_result(
            {
                "presence": "present",
                "security_txt_present": True,
                "rfc9116_valid": False,
                "validation_errors": ["malformed_line:3", "expired"],
                "validation_warnings": ["expires_more_than_one_year_ahead"],
            }
        )
        self.assertEqual("invalid", invalid["classification"])
        self.assertEqual(["malformed_line", "expired"], invalid["error_codes"])
        self.assertIn("syntax_error", invalid["flags"])
        self.assertIn("long_expiry", invalid["flags"])

        blocked = annotate_result(
            {
                "presence": "http_inconclusive",
                "http_status": 403,
                "security_txt_present": False,
                "rfc9116_valid": False,
            }
        )
        self.assertEqual("blocked", blocked["classification"])
        self.assertIn("possible_waf", blocked["flags"])

        unreachable = annotate_result(
            {
                "presence": "inconclusive",
                "http_responded": False,
                "transport_error": "timeout",
                "security_txt_present": False,
                "rfc9116_valid": False,
            }
        )
        self.assertEqual("unreachable", unreachable["classification"])
        self.assertIn("timeout", unreachable["flags"])

    def test_extension_fields_have_queryable_flags(self):
        result = annotate_result(
            {
                "presence": "present",
                "security_txt_present": True,
                "rfc9116_valid": True,
                "validation_errors": [],
                "validation_warnings": [],
                "extension_fields": ["Bug-Bounty", "Signature"],
                "registered_extension_fields": ["Bug-Bounty"],
                "unknown_fields": ["Signature"],
            }
        )
        self.assertIn("extension_fields", result["flags"])
        self.assertIn("registered_extension_fields", result["flags"])
        self.assertIn("unknown_fields", result["flags"])
