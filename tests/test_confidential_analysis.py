import unittest

from ui_server import (
    _analyse_confidential_text,
    _luhn_valid,
    _mask_card,
    _mask_email,
    _mask_password,
    _mask_token,
    _parse_pipe_payment_record,
)


def synthetic_luhn(prefix: str) -> str:
    for digit in "0123456789":
        candidate = f"{prefix}{digit}"
        if _luhn_valid(candidate):
            return candidate
    raise AssertionError("Could not create synthetic Luhn value")


class ConfidentialAnalysisSafetyTests(unittest.TestCase):
    def test_luhn_validation_with_synthetic_card(self):
        card = synthetic_luhn("4" + "1" * 14)
        self.assertTrue(_luhn_valid(card))
        self.assertFalse(_luhn_valid(card[:-1] + str((int(card[-1]) + 1) % 10)))

    def test_masking_rules_do_not_return_raw_values(self):
        card = synthetic_luhn("4" + "1" * 14)
        self.assertEqual(_mask_card(card), f"4##############{card[-1]}")
        self.assertEqual(_mask_password("secretpass"), "s#########")
        self.assertEqual(_mask_token("tok_abcdefghijklmnopqrstuvwxyz"), "tok########################xyz")
        self.assertEqual(_mask_email("jane.demo@example.com"), "j********@example.com")

    def test_analysis_returns_masked_synthetic_findings_only(self):
        card = synthetic_luhn("4" + "1" * 14)
        sample = (
            f"demo@example.com|{card}|12/29|cvv=123|"
            "password=secretpass|api_key=tok_abcdefghijklmnopqrstuvwxyz|ip=192.0.2.10"
        )
        findings = _analyse_confidential_text("synthetic_demo.txt", sample)
        rendered = str(findings)
        self.assertTrue(any(item["detected_type"] == "Payment Card" for item in findings))
        self.assertIn(f"4##############{card[-1]}", rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertNotIn(card, rendered)
        self.assertNotIn("cvv=123", rendered.lower())
        self.assertNotIn("secretpass", rendered)
        self.assertNotIn("tok_abcdefghijklmnopqrstuvwxyz", rendered)

    def test_pipe_separated_payment_record_is_structured_and_masked(self):
        card = synthetic_luhn("5" + "5" * 14)
        line = "|".join([
            card, "8/2024", "123", "NUMAST NATNARI", "", "", "", "", "", "",
            "6012345621", "name.synthetic@hotmail.com", "--", "45.76.12.34",
            "Mozilla/5.0 Chrome/10987654 Safari/537.36",
        ])
        parsed = _parse_pipe_payment_record(line)
        self.assertIsNotNone(parsed)
        fields = parsed["parsed_fields"]
        self.assertEqual(parsed["masked_value"], f"5##############{card[-1]}")
        self.assertEqual(fields["masked_card_number"], parsed["masked_value"])
        self.assertEqual(fields["expiry_date"], "8/2024")
        self.assertEqual(fields["cvv"], "[REDACTED]")
        self.assertEqual(fields["address_line_1"], "N/A")
        self.assertEqual(fields["masked_phone"], "60######21")
        self.assertEqual(fields["masked_email"], "n*************@hotmail.com")
        self.assertEqual(fields["masked_ip_address"], "45.76.#.#")
        rendered = str(parsed)
        self.assertNotIn(card, rendered)
        self.assertNotIn("123|NUMAST", rendered)
        self.assertNotIn("45.76.12.34", rendered)
        self.assertNotIn("10987654", rendered)

    def test_pipe_analysis_masked_value_is_only_card_number(self):
        card = synthetic_luhn("5" + "5" * 14)
        findings = _analyse_confidential_text(
            "synthetic_pipe.txt",
            "|".join([
                card, "8/2024", "999", "CARD HOLDER", "", "", "", "", "", "",
                "6012345621", "demo@example.com", "--", "45.76.12.34", "Chrome/10987654",
            ]),
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["detected_type"], "Payment Card Exposure")
        self.assertEqual(finding["masked_value"], f"5##############{card[-1]}")
        self.assertNotIn("|", finding["masked_value"])
        self.assertEqual(finding["parsed_fields"]["cvv"], "[REDACTED]")
        rendered = str(findings)
        self.assertNotIn(card, rendered)
        self.assertNotIn("999", rendered)

    def test_source_file_column_not_rendered_and_contrast_styles_exist(self):
        with open("index.html", encoding="utf-8") as html_file:
            html = html_file.read()
        with open("style.css", encoding="utf-8") as css_file:
            css = css_file.read()
        table_start = html.index('<table class="data-table confidential-table">')
        table_end = html.index("</table>", table_start)
        confidential_table = html[table_start:table_end]
        self.assertNotIn("<th>Source File</th>", confidential_table)
        self.assertIn(".confidential-filter-row .search-input option", css)
        self.assertIn(".confidential-table td", css)
        self.assertIn(".confidential-field-value", css)


if __name__ == "__main__":
    unittest.main()
