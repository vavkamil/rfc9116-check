import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from securitytxt_scan.cli import apply_config, build_parser, read_domains


class CliTests(unittest.TestCase):
    def test_read_domains_uses_input_order_and_ignores_duplicates(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text(
                "# comment\nExample.COM.\n\nexample.com\nother.example\n",
                encoding="utf-8",
            )

            self.assertEqual(["example.com", "other.example"], read_domains(path))
            self.assertEqual(["example.com"], read_domains(path, limit=1))

    def test_read_domains_rejects_csv_rows(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "domains.txt"
            path.write_text("1,example.com\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "invalid domain"):
                read_domains(path)

    def test_cli_derives_output_directory_from_input_and_limit(self):
        parser = build_parser()
        full = parser.parse_args(["lists/czech-sites.txt"])
        apply_config(full, parser)
        self.assertEqual("lists/czech-sites.txt", str(full.input))
        self.assertEqual("results-czech-sites", str(full.output_dir))

        partial = parser.parse_args(["lists/czech-sites.txt", "--limit", "20"])
        apply_config(partial, parser)
        self.assertEqual("results-czech-sites-first-20", str(partial.output_dir))
