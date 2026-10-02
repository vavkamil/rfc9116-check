import unittest

from securitytxt_scan.display import format_progress_row, progress_details
from securitytxt_scan.validation import (
    parse_content_type,
    parse_rfc3339,
    valid_language_tag,
    validate_security_txt,
)

from .helpers import NOW, URL, validate


class ValidationTests(unittest.TestCase):
    def test_pgp_presence_is_information_not_warning(self):
        result = validate(
            "-----BEGIN PGP SIGNED MESSAGE-----\n"
            "Hash: SHA256\n"
            "\n"
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "-----BEGIN PGP SIGNATURE-----\n"
            "abc123\n"
            "-----END PGP SIGNATURE-----\n"
        )
        self.assertIn("pgp_present", result["validation_info"])
        self.assertNotIn(
            "pgp_signature_not_cryptographically_verified",
            result["validation_warnings"],
        )

    def test_malformed_content_type_does_not_default_to_text_plain(self):
        self.assertEqual(
            ("nonsense", "utf-8"),
            parse_content_type("nonsense; charset=utf-8"),
        )
        result = validate(
            "Contact: mailto:security@example.cz\nExpires: 2027-01-01T00:00:00Z\n",
            "nonsense; charset=utf-8",
        )
        self.assertIn("content_type_not_text_plain", result["validation_errors"])

    def test_valid_minimal_file(self):
        result = validate(
            "Contact: mailto:security@example.cz\nExpires: 2027-01-01T00:00:00Z\n"
        )
        self.assertTrue(result["rfc9116_valid"])
        self.assertEqual([], result["validation_errors"])

    def test_missing_required_fields(self):
        result = validate("Policy: https://example.cz/security\n")
        self.assertFalse(result["rfc9116_valid"])
        self.assertIn("missing_contact", result["validation_errors"])
        self.assertIn("missing_expires", result["validation_errors"])

    def test_expired_file_is_not_currently_valid(self):
        result = validate(
            "Contact: mailto:security@example.cz\nExpires: 2025-01-01T00:00:00Z\n"
        )
        self.assertIn("expired", result["validation_errors"])
        self.assertTrue(result["expired"])

    def test_mime_type_and_charset_are_required(self):
        result = validate(
            "Contact: mailto:security@example.cz\nExpires: 2027-01-01T00:00:00Z\n",
            "text/html",
        )
        self.assertIn("content_type_not_text_plain", result["validation_errors"])
        self.assertIn("missing_utf8_charset", result["validation_errors"])

    def test_invalid_utf8(self):
        result = validate_security_txt(
            b"Contact: mailto:x@example.cz\nExpires: \xff\n",
            "text/plain; charset=utf-8",
            URL,
            URL,
            now=NOW,
        )
        self.assertIn("invalid_utf8", result["validation_errors"])
        self.assertIsNotNone(result["body_base64"])

    def test_insecure_web_uri(self):
        result = validate(
            "Contact: http://example.cz/report\nExpires: 2027-01-01T00:00:00Z\n"
        )
        self.assertIn("insecure_web_uri:contact:1", result["validation_errors"])

    def test_bare_email_contact_requires_mailto_scheme(self):
        result = validate(
            "Contact: security@example.cz\nExpires: 2027-01-01T00:00:00Z\n"
        )
        self.assertIn("contact_missing_mailto:1", result["validation_errors"])
        row = format_progress_row(
            {
                "domain": "example.cz",
                "dns_resolved": True,
                "http_status": 200,
                "presence": "present",
                "security_txt_present": True,
                "rfc9116_valid": False,
                "validation_errors": result["validation_errors"],
            },
            position=1,
            number_width=1,
            domain_width=18,
        )
        self.assertIn("contact missing mailto", row)

    def test_unknown_extension_field_is_allowed_and_recorded(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "X-Funny: surprise\n"
        )
        self.assertTrue(result["rfc9116_valid"])
        self.assertEqual(["X-Funny"], result["extension_fields"])
        self.assertEqual([], result["registered_extension_fields"])
        self.assertEqual(["X-Funny"], result["unknown_fields"])

    def test_registered_extension_field_is_distinguished_from_unknown(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Bug-Bounty: False\n"
        )
        self.assertTrue(result["rfc9116_valid"])
        self.assertEqual(["Bug-Bounty"], result["extension_fields"])
        self.assertEqual(["Bug-Bounty"], result["registered_extension_fields"])
        self.assertEqual([], result["unknown_fields"])

    def test_malformed_line_and_missing_final_newline(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "this is not a field"
        )
        self.assertIn("missing_final_line_separator", result["validation_errors"])
        self.assertIn("malformed_line:3", result["validation_errors"])

    def test_empty_fields_are_distinguished_from_malformed_lines(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Policy: \n"
            "Signature: \n"
        )
        self.assertIn("empty_field_value:Policy", result["validation_errors"])
        self.assertIn("empty_field_value:Signature", result["validation_errors"])
        self.assertNotIn("malformed_line:3", result["validation_errors"])
        self.assertIn("Signature", result["unknown_fields"])

    def test_duplicate_singleton_fields(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Expires: 2027-02-01T00:00:00Z\n"
            "Preferred-Languages: cs\n"
            "Preferred-Languages: en\n"
        )
        self.assertIn("multiple_expires", result["validation_errors"])
        self.assertIn("multiple_preferred_languages", result["validation_errors"])

    def test_canonical_mismatch_is_warning(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Canonical: https://other.example/security.txt\n"
        )
        self.assertTrue(result["rfc9116_valid"])
        self.assertIn(
            "canonical_does_not_match_retrieval_url",
            result["validation_warnings"],
        )

    def test_canonical_default_https_port_is_equivalent(self):
        result = validate_security_txt(
            b"Contact: mailto:security@example.cz\n"
            b"Expires: 2027-01-01T00:00:00Z\n"
            b"Canonical: https://www.example.cz/.well-known/security.txt\n",
            "text/plain; charset=utf-8",
            URL,
            "https://www.example.cz:443/.well-known/security.txt",
            now=NOW,
        )
        self.assertNotIn(
            "canonical_does_not_match_retrieval_url",
            result["validation_warnings"],
        )

    def test_rfc3339_parser_accepts_z_and_offsets(self):
        self.assertIsNotNone(parse_rfc3339("2027-01-01T00:00:00Z"))
        self.assertIsNotNone(parse_rfc3339("2027-01-01t00:00:00.123+01:00"))
        self.assertIsNone(parse_rfc3339("2027-01-01"))

    def test_common_and_complex_bcp47_language_tags(self):
        self.assertTrue(valid_language_tag("cs"))
        self.assertTrue(valid_language_tag("en-US"))
        self.assertTrue(valid_language_tag("zh-Hant-TW"))
        self.assertTrue(valid_language_tag("sl-rozaj-biske"))
        self.assertTrue(valid_language_tag("de-CH-1901"))
        self.assertTrue(valid_language_tag("en-a-aaa-b-bbb-x-private"))
        self.assertTrue(valid_language_tag("i-default"))
        self.assertTrue(valid_language_tag("x-private"))
        self.assertFalse(valid_language_tag("cz"))
        self.assertFalse(valid_language_tag("English"))
        self.assertFalse(valid_language_tag("en_US"))
        self.assertFalse(valid_language_tag("en-a"))

        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Preferred-Languages: English, French\n"
        )
        self.assertIn(
            "invalid_preferred_languages:English, French",
            result["validation_errors"],
        )

    def test_unregistered_well_known_references_are_invalid(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Policy: https://example.cz/.well-known/security-policy.html\n"
        )
        self.assertIn(
            "unregistered_well_known_uri:policy:1:security-policy.html",
            result["validation_errors"],
        )
        self.assertIn("unregistered well-known URI", progress_details(result))

    def test_registered_well_known_references_are_allowed(self):
        result = validate(
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
            "Encryption: https://example.cz/.well-known/keybase.txt\n"
        )
        self.assertTrue(result["rfc9116_valid"])

    def test_unicode_nfc_is_a_recommendation_not_a_validity_error(self):
        result = validate(
            "# cafe\u0301\n"
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
        )
        self.assertTrue(result["rfc9116_valid"])
        self.assertIn("not_unicode_nfc", result["validation_warnings"])

    def test_net_unicode_rejects_controls_and_unassigned_code_points(self):
        result = validate(
            "# bad\u0080\u0378\n"
            "Contact: mailto:security@example.cz\n"
            "Expires: 2027-01-01T00:00:00Z\n"
        )
        self.assertIn("disallowed_control_character", result["validation_errors"])
        self.assertIn(
            "unassigned_unicode_code_point",
            result["validation_errors"],
        )

    def test_exactly_one_year_expiry_gets_recommendation_warning(self):
        result = validate(
            "Contact: mailto:security@example.cz\nExpires: 2027-10-01T00:00:00Z\n"
        )
        self.assertTrue(result["rfc9116_valid"])
        self.assertIn("expires_more_than_one_year_ahead", result["validation_warnings"])

    def test_insecure_redirect_is_an_explicit_error(self):
        result = validate_security_txt(
            b"Contact: mailto:security@example.cz\nExpires: 2027-01-01T00:00:00Z\n",
            "text/plain; charset=utf-8",
            URL,
            URL,
            now=NOW,
            extra_errors=["insecure_redirect"],
        )
        self.assertIn("insecure_redirect", result["validation_errors"])
        self.assertIn("HTTP redirect", progress_details(result))
