import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from mekai_open.analysis import (
    AnalysisConfiguration,
    analyze_capture,
    load_analysis_configuration,
)
from mekai_open.observations import RobotIdentity, RobotTarget


ROOT = Path(__file__).parents[1]
CAPTURE = ROOT / "fixtures" / "captures" / "state_gap_missingness.synthetic.capture.jsonl"
RUN_SCHEMA = ROOT / "schemas" / "analysis-run-0.1.schema.json"
CONFIG_SCHEMA = ROOT / "schemas" / "config-0.1.schema.json"


class AnalysisConfigurationTests(unittest.TestCase):
    def test_strict_configuration_loads_and_matches_schema(self) -> None:
        document = {
            "schema": "mekai.analysis_config/0.1",
            "source_id": "synthetic-run",
            "robots": [
                {
                    "subject_id": "R1",
                    "manufacturer": "SyntheticVendor",
                    "serial_number": "R-A",
                }
            ],
            "limits": {"message_bytes": 8_388_608},
        }
        schema = json.loads(CONFIG_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(document)), [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = load_analysis_configuration(path)
        self.assertEqual(loaded.to_dict(), document)

    def test_duplicate_subject_or_identity_fails_closed(self) -> None:
        target = RobotTarget("R1", RobotIdentity("Vendor", "A"))
        with self.assertRaisesRegex(ValueError, "subject IDs"):
            AnalysisConfiguration(
                "source", (target, RobotTarget("R1", RobotIdentity("Vendor", "B")))
            )
        with self.assertRaisesRegex(ValueError, "identities"):
            AnalysisConfiguration(
                "source", (target, RobotTarget("R2", RobotIdentity("Vendor", "A")))
            )

    def test_duplicate_json_keys_are_rejected(self) -> None:
        payload = (
            b'{"schema":"mekai.analysis_config/0.1","source_id":"a",'
            b'"source_id":"b","robots":[],"limits":{"message_bytes":1}}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_bytes(payload)
            with self.assertRaisesRegex(ValueError, "strict JSON"):
                load_analysis_configuration(path)


class AnalysisRunTests(unittest.TestCase):
    def setUp(self) -> None:
        self.configuration = AnalysisConfiguration(
            "synthetic-run",
            (RobotTarget("R1", RobotIdentity("SyntheticVendor", "R-A")),),
        )

    def test_all_function_families_execute_in_one_run(self) -> None:
        run = analyze_capture(CAPTURE, self.configuration)
        document = run.to_dict()
        self.assertEqual(document["summary"]["function_result_count"], 13)
        self.assertEqual(len(document["results"]), 13)
        self.assertEqual(
            len({row["qualified_id"] for row in document["results"]}), 13
        )
        self.assertTrue(document["exceptions"])
        schema = json.loads(RUN_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            list(Draft202012Validator(schema).iter_errors(document)), []
        )

    def test_analysis_is_byte_deterministic(self) -> None:
        first = analyze_capture(CAPTURE, self.configuration)
        second = analyze_capture(CAPTURE, self.configuration)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.analysis_id, second.analysis_id)

    def test_run_never_serializes_absolute_input_path(self) -> None:
        run = analyze_capture(CAPTURE, self.configuration)
        self.assertNotIn(str(CAPTURE), run.to_json())
        self.assertNotIn(str(ROOT), run.to_json())


if __name__ == "__main__":
    unittest.main()
