import io
import json
import unittest
from contextlib import redirect_stdout

from mekai_open.cli import main


class CliTests(unittest.TestCase):
    def test_function_list_reports_identity_and_basis(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["specs", "list"])
        self.assertEqual(code, 0)
        lines = output.getvalue().splitlines()
        self.assertTrue(lines)
        self.assertTrue(
            all(line.endswith(("\tREPORTED", "\tINFERRED")) for line in lines)
        )

    def test_describe_returns_json_contract(self) -> None:
        qualified_id = (
            "vda.inferred_protocol_finished_orders_per_observed_robot_hour@0.1.0"
        )
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["specs", "describe", qualified_id])
        self.assertEqual(code, 0)
        document = json.loads(output.getvalue())
        self.assertEqual(document["qualified_id"], qualified_id)
        self.assertEqual(document["basis"], "INFERRED")


if __name__ == "__main__":
    unittest.main()
