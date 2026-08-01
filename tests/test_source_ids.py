import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import mekai_open
from mekai_open.capture_jsonl import (
    CaptureControlRecord,
    CaptureReader,
    CaptureReaderArgumentError,
    CaptureRecordKind,
)
from mekai_open.contracts import InputReference
from mekai_open.source_ids import validate_source_id


ROOT = Path(__file__).parents[1]


class SourceIdContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        config = json.loads(
            (ROOT / "schemas" / "config-0.1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        result = json.loads(
            (ROOT / "schemas" / "function-result-0.1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(config)
        Draft202012Validator.check_schema(result)
        cls.source_id_schemas = (
            config["properties"]["source_id"],
            result["properties"]["input_references"]["items"]["properties"][
                "source_id"
            ],
        )

    def test_positive_and_boundary_values_match_python_and_schemas(self) -> None:
        values = (
            "a",
            "A0._-z",
            "_",
            "-source",
            ".source",
            "source.",
            "...",
            "a" * 128,
        )
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(validate_source_id(value), value)
                self._assert_schema_acceptance(value, expected=True)
                self._input_reference(value)
                CaptureReader("unused.capture.jsonl", value)

    def test_negative_values_match_python_and_schemas(self) -> None:
        values: tuple[object, ...] = (
            None,
            1,
            "",
            "a" * 129,
            ".",
            "..",
            "/absolute",
            "relative/path",
            "relative\\path",
            "../traversal",
            "a/../b",
            "..\\traversal",
            "C:relative",
            "C:\\relative",
            " space",
            "space ",
            "white space",
            "\nleading",
            "trailing\n",
            "tab\tvalue",
            "line\nvalue",
            "carriage\rvalue",
            "trailing\r",
            "nul\x00value",
            "bidi\u202evalue",
            "nonascii-é",
            "emoji-😀",
        )
        for value in values:
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    validate_source_id(value)
                self._assert_schema_acceptance(value, expected=False)
                with self.assertRaises(ValueError):
                    self._input_reference(value)  # type: ignore[arg-type]
                with self.assertRaises(CaptureReaderArgumentError):
                    CaptureReader(
                        "unused.capture.jsonl", value  # type: ignore[arg-type]
                    )

    def test_internal_typed_records_reuse_the_same_contract(self) -> None:
        with self.assertRaises(ValueError):
            CaptureControlRecord(
                source_id="../capture",
                locator="line:1",
                kind=CaptureRecordKind.CAPTURE_START,
                sequence=0,
                observation_time_ns=0,
                receive_monotonic_ns=None,
                capture_accepted=True,
                capture_diagnostics=(),
                complete=None,
            )

    def test_schema_copies_are_identical_and_validator_is_not_public(self) -> None:
        self.assertEqual(self.source_id_schemas[0], self.source_id_schemas[1])
        self.assertNotIn("validate_source_id", mekai_open.__all__)
        self.assertFalse(hasattr(mekai_open, "validate_source_id"))

    def _assert_schema_acceptance(
        self, value: object, *, expected: bool
    ) -> None:
        for index, schema in enumerate(self.source_id_schemas):
            with self.subTest(schema=index):
                valid = not list(Draft202012Validator(schema).iter_errors(value))
                self.assertIs(valid, expected)

    @staticmethod
    def _input_reference(source_id: str) -> InputReference:
        return InputReference(
            source_id=source_id,
            input_sha256="0" * 64,
            locator="line:1",
            message_family="state",
        )


if __name__ == "__main__":
    unittest.main()
