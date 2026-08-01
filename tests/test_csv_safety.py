import unittest

from mekai_open.csv_safety import spreadsheet_safe_cell


class CsvSafetyTests(unittest.TestCase):
    def test_formula_prefixes_are_neutralized(self) -> None:
        for value in (
            "=1+1",
            "+SUM(A1:A2)",
            "-2+3",
            "@cmd",
            "\tformula",
            "\rformula",
        ):
            with self.subTest(value=value):
                self.assertEqual(spreadsheet_safe_cell(value), "'" + value)

    def test_non_formula_values_are_unchanged(self) -> None:
        self.assertEqual(spreadsheet_safe_cell("text"), "text")
        self.assertEqual(spreadsheet_safe_cell(42), "42")
        self.assertEqual(spreadsheet_safe_cell(-42), "-42")
        self.assertEqual(spreadsheet_safe_cell(-1.5), "-1.5")
        self.assertEqual(spreadsheet_safe_cell(None), "")

    def test_non_finite_numbers_are_rejected(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    spreadsheet_safe_cell(value)


if __name__ == "__main__":
    unittest.main()
