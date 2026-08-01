import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from mekai_open.contracts import (
    Coverage,
    EvaluationWindow,
    FieldRequirement,
    FunctionResult,
    FunctionSpec,
    InputReference,
    MissingInterval,
    ResultBasis,
    ResultScope,
    ResultStatus,
    ScopeKind,
)
from mekai_open.function_registry import get_function_spec
from mekai_open.json_safety import contains_invalid_unicode_scalar


class ContractTests(unittest.TestCase):
    def test_result_serialization_is_deterministic(self) -> None:
        result = FunctionResult(
            function_id="vda.reported_driving_duration",
            function_version="0.1.0",
            status=ResultStatus.PARTIAL,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, ("R1",)),
            window=EvaluationWindow(0, 100_000_000_000),
            coverage=Coverage(
                eligible_duration_ns=100_000_000_000,
                observed_duration_ns=70_000_000_000,
                missing_intervals=(
                    MissingInterval(
                        50_000_000_000,
                        80_000_000_000,
                        "STATE_CARRY_FORWARD_EXPIRED",
                    ),
                ),
            ),
            method_version="reported-driving-duration/0.1.0",
            value={"driving_seconds": 20, "not_driving_seconds": 50},
            unit="seconds",
            input_references=(
                InputReference(
                    source_id="fixture",
                    input_sha256="0" * 64,
                    locator="line:1",
                    message_family="state",
                ),
            ),
            diagnostics=("30 seconds unobserved",),
        )
        first = result.to_json()
        second = result.to_json()
        self.assertEqual(first, second)
        decoded = json.loads(first)
        self.assertEqual(decoded["coverage"]["ratio"], 0.7)
        self.assertEqual(decoded["coverage"]["known_missing_interval_count"], 1)
        self.assertIs(
            decoded["coverage"]["missing_interval_details_truncated"], False
        )
        self.assertEqual(decoded["basis"], "REPORTED")
        self.assertEqual(
            decoded["scope"], {"kind": "ROBOT", "subject_ids": ["R1"]}
        )

    def test_not_computable_requires_reason_and_no_value(self) -> None:
        with self.assertRaises(ValueError):
            FunctionResult(
                function_id="vda.reported_paused_duration",
                function_version="0.1.0",
                status=ResultStatus.NOT_COMPUTABLE,
                basis=ResultBasis.REPORTED,
                scope=ResultScope(ScopeKind.ROBOT, ("R1",)),
                window=EvaluationWindow(0, 1),
                coverage=Coverage(1, 0),
                method_version="paused/0.1.0",
            )
        with self.assertRaises(ValueError):
            FunctionResult(
                function_id="vda.reported_paused_duration",
                function_version="0.1.0",
                status=ResultStatus.NOT_COMPUTABLE,
                basis=ResultBasis.REPORTED,
                scope=ResultScope(ScopeKind.ROBOT, ("R1",)),
                window=EvaluationWindow(0, 1),
                coverage=Coverage(1, 0),
                method_version="paused/0.1.0",
                value=0,
                diagnostics=("NO_SOURCE",),
            )

    def test_coverage_exposes_and_validates_interval_detail_completeness(
        self,
    ) -> None:
        interval = MissingInterval(10, 20, "COLLECTOR_SESSION_GAP")
        coverage = Coverage(
            eligible_duration_ns=100,
            observed_duration_ns=80,
            missing_intervals=(interval,),
            known_missing_interval_count=2,
            missing_interval_details_truncated=True,
        )
        self.assertEqual(coverage.known_missing_interval_count, 2)
        self.assertIs(coverage.missing_interval_details_truncated, True)

        invalid = (
            {"known_missing_interval_count": 0},
            {
                "known_missing_interval_count": 1,
                "missing_interval_details_truncated": True,
            },
            {"known_missing_interval_count": True},
        )
        for overrides in invalid:
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    Coverage(
                        eligible_duration_ns=100,
                        observed_duration_ns=80,
                        missing_intervals=(interval,),
                        **overrides,
                    )

    def test_coverage_can_explicitly_withhold_unsupported_duration(self) -> None:
        interval = MissingInterval(10, 20, "COLLECTOR_SESSION_GAP")
        coverage = Coverage(
            eligible_duration_ns=100,
            observed_duration_ns=None,
            missing_intervals=(interval,),
            known_missing_interval_count=2,
            missing_interval_details_truncated=True,
        )
        self.assertIsNone(coverage.observed_duration_ns)
        self.assertIsNone(coverage.ratio)
        self.assertIsNone(coverage.to_dict()["observed_duration_ns"])

        with self.assertRaisesRegex(ValueError, "unavailable observed duration"):
            Coverage(
                eligible_duration_ns=100,
                observed_duration_ns=None,
                missing_intervals=(interval,),
            )

    def test_schema_limits_null_observed_duration_to_partial_results(self) -> None:
        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schemas"
                / "function-result-0.1.schema.json"
            ).read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema)
        partial = FunctionResult(
            function_id="vda.state_stream_health",
            function_version="0.1.0",
            status=ResultStatus.PARTIAL,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.SOURCE, ("fixture",)),
            window=EvaluationWindow(0, 100),
            coverage=Coverage(
                eligible_duration_ns=100,
                observed_duration_ns=None,
                missing_intervals=(
                    MissingInterval(10, 20, "COLLECTOR_SESSION_GAP"),
                ),
                known_missing_interval_count=2,
                missing_interval_details_truncated=True,
            ),
            method_version="0.1.0",
            value={},
            diagnostics=("COVERAGE_DURATION_UNAVAILABLE",),
        ).to_dict()
        self.assertEqual(list(validator.iter_errors(partial)), [])
        partial["status"] = "NOT_COMPUTABLE"
        partial["value"] = None
        self.assertTrue(list(validator.iter_errors(partial)))

    def test_computed_result_rejects_truncated_coverage_details(self) -> None:
        with self.assertRaisesRegex(ValueError, "truncated coverage"):
            FunctionResult(
                function_id="vda.state_stream_health",
                function_version="0.1.0",
                status=ResultStatus.COMPUTED,
                basis=ResultBasis.REPORTED,
                scope=ResultScope(ScopeKind.SOURCE, ("fixture",)),
                window=EvaluationWindow(0, 100),
                coverage=Coverage(
                    eligible_duration_ns=100,
                    observed_duration_ns=80,
                    missing_intervals=(
                        MissingInterval(10, 20, "COLLECTOR_SESSION_GAP"),
                    ),
                    known_missing_interval_count=2,
                    missing_interval_details_truncated=True,
                ),
                method_version="0.1.0",
                value={},
            )

    def test_undefined_window_is_limited_to_not_computable_zero_coverage(self) -> None:
        result = FunctionResult(
            function_id="vda.state_stream_health",
            function_version="0.1.0",
            status=ResultStatus.NOT_COMPUTABLE,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.SOURCE, ("fixture",)),
            window=None,
            coverage=Coverage(0, 0),
            method_version="0.1.0",
            diagnostics=("WINDOW_UNDEFINED",),
        )
        self.assertIsNone(result.to_dict()["window"])

        with self.assertRaisesRegex(ValueError, "require a window"):
            FunctionResult(
                function_id="vda.state_stream_health",
                function_version="0.1.0",
                status=ResultStatus.COMPUTED,
                basis=ResultBasis.REPORTED,
                scope=ResultScope(ScopeKind.SOURCE, ("fixture",)),
                window=None,
                coverage=Coverage(0, 0),
                method_version="0.1.0",
                value={},
            )
        with self.assertRaisesRegex(ValueError, "zero coverage"):
            FunctionResult(
                function_id="vda.state_stream_health",
                function_version="0.1.0",
                status=ResultStatus.NOT_COMPUTABLE,
                basis=ResultBasis.REPORTED,
                scope=ResultScope(ScopeKind.SOURCE, ("fixture",)),
                window=None,
                coverage=Coverage(1, 0),
                method_version="0.1.0",
                diagnostics=("WINDOW_UNDEFINED",),
            )

    def test_result_rejects_non_finite_values(self) -> None:
        with self.assertRaises(ValueError):
            FunctionResult(
                function_id="vda.reported_battery_state_of_charge",
                function_version="0.1.0",
                status=ResultStatus.COMPUTED,
                basis=ResultBasis.REPORTED,
                scope=ResultScope(ScopeKind.ROBOT, ("R1",)),
                window=EvaluationWindow(0, 1),
                coverage=Coverage(1, 1),
                method_version="battery/0.1.0",
                value=float("nan"),
            )

    def test_shared_unicode_scalar_check_covers_surrogate_boundaries(self) -> None:
        self.assertTrue(contains_invalid_unicode_scalar("\ud800"))
        self.assertTrue(contains_invalid_unicode_scalar("\udfff"))
        self.assertFalse(contains_invalid_unicode_scalar("😀"))

    def test_result_rejects_surrogates_in_values_keys_and_fields(self) -> None:
        invalid_values = (
            "\ud800",
            {"\udfff": 1},
            {"outer": [{"nested": "\ud800"}]},
        )
        for value in invalid_values:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(
                    ValueError, "invalid Unicode scalar value"
                ):
                    self._computed_result(value)

        with self.assertRaisesRegex(
            ValueError, "invalid Unicode scalar value"
        ):
            self._computed_result(1, unit="\udfff")

    def test_function_spec_rejects_surrogate_parameter_key(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "invalid Unicode scalar value"
        ):
            FunctionSpec(
                function_id="test.invalid_unicode",
                version="0.1.0",
                required_message_families=("state",),
                required_fields=(),
                method="test",
                basis=ResultBasis.REPORTED,
                missing_data_requirements=(),
                result_schema="mekai.function_result/0.1",
                fixture_ids=("truth.test",),
                parameters={"\ud800": "value"},
            )

    def test_accepted_contract_json_is_utf8_encodable(self) -> None:
        result = self._computed_result({"emoji": ["😀"]}, unit="🚗")
        encoded_result = result.to_json().encode("utf-8")
        self.assertIn("😀".encode("utf-8"), encoded_result)

        spec = FunctionSpec(
            function_id="test.valid_unicode",
            version="0.1.0",
            required_message_families=("state",),
            required_fields=(),
            method="emoji 😀",
            basis=ResultBasis.REPORTED,
            missing_data_requirements=(),
            result_schema="mekai.function_result/0.1",
            fixture_ids=("truth.unicode",),
            parameters={"emoji": "😀"},
        )
        encoded_spec = json.dumps(
            spec.to_dict(), ensure_ascii=False, sort_keys=True
        ).encode("utf-8")
        self.assertIn("😀".encode("utf-8"), encoded_spec)

    def test_function_parameters_are_read_only(self) -> None:
        spec: FunctionSpec = get_function_spec(
            "vda.reported_connection_state_duration@0.1.0"
        )
        with self.assertRaises(TypeError):
            spec.parameters["unsafe"] = True  # type: ignore[index]

    def test_nested_function_parameters_are_immutable_copies(self) -> None:
        source = {"thresholds": {"values": [1, 2]}}
        spec = FunctionSpec(
            function_id="test.nested_parameters",
            version="0.1.0",
            required_message_families=("state",),
            required_fields=(),
            method="test",
            basis=ResultBasis.REPORTED,
            missing_data_requirements=(),
            result_schema="mekai.function_result/0.1",
            fixture_ids=("truth.test",),
            parameters=source,
        )

        source["thresholds"]["values"].append(3)
        self.assertEqual(
            spec.to_dict()["parameters"],
            {"thresholds": {"values": [1, 2]}},
        )
        with self.assertRaises(AttributeError):
            spec.parameters["thresholds"]["values"].append(4)

        exported = spec.to_dict()
        exported["parameters"]["thresholds"]["values"].append(5)
        self.assertEqual(
            spec.to_dict()["parameters"],
            {"thresholds": {"values": [1, 2]}},
        )

    def test_nested_result_values_are_immutable_copies(self) -> None:
        source = {"seconds": [1, 2]}
        result = FunctionResult(
            function_id="test.nested_result",
            function_version="0.1.0",
            status=ResultStatus.COMPUTED,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, ("R1",)),
            window=EvaluationWindow(0, 1),
            coverage=Coverage(1, 1),
            method_version="test/0.1.0",
            value=source,
        )

        source["seconds"].append(3)
        self.assertEqual(result.to_dict()["value"], {"seconds": [1, 2]})
        with self.assertRaises(AttributeError):
            result.value["seconds"].append(4)

    def test_coverage_rejects_over_observation(self) -> None:
        with self.assertRaises(ValueError):
            Coverage(eligible_duration_ns=1, observed_duration_ns=2)

    def test_result_scope_rejects_duplicate_subjects(self) -> None:
        with self.assertRaises(ValueError):
            ResultScope(ScopeKind.OBSERVED_ROBOT_COHORT, ("R1", "R1"))

    def test_source_scope_remains_available_for_source_health(self) -> None:
        scope = ResultScope(ScopeKind.SOURCE, ("capture-1",))
        self.assertEqual(
            scope.to_dict(),
            {"kind": "SOURCE", "subject_ids": ["capture-1"]},
        )

    def test_contracts_reject_unsupported_message_families(self) -> None:
        with self.assertRaises(ValueError):
            InputReference(
                source_id="fixture",
                input_sha256="0" * 64,
                locator="line:1",
                message_family="factsheet",
            )
        with self.assertRaises(ValueError):
            FieldRequirement("factsheet", ("headerId",))

    def test_function_spec_rejects_schema_drift(self) -> None:
        with self.assertRaises(ValueError):
            FunctionSpec(
                function_id="test.invalid_result_schema",
                version="0.1.0",
                required_message_families=("state",),
                required_fields=(),
                method="test",
                basis=ResultBasis.REPORTED,
                missing_data_requirements=(),
                result_schema="mekai.function_result/9.9",
                fixture_ids=(),
            )

    def test_function_spec_canonicalizes_set_like_fields(self) -> None:
        spec = FunctionSpec(
            function_id="test.canonical_spec",
            version="0.1.0",
            required_message_families=("state", "order"),
            required_fields=(
                FieldRequirement("state", ("timestamp", "headerId")),
                FieldRequirement("order", ("orderUpdateId", "orderId")),
            ),
            method="test",
            basis=ResultBasis.REPORTED,
            missing_data_requirements=("z", "a"),
            result_schema="mekai.function_result/0.1",
            fixture_ids=("truth.z", "truth.a"),
        )
        exported = spec.to_dict()
        self.assertEqual(
            exported["required_message_families"], ["order", "state"]
        )
        self.assertEqual(
            exported["required_fields"][0]["fields"],
            ["orderId", "orderUpdateId"],
        )
        self.assertEqual(exported["missing_data_requirements"], ["a", "z"])
        self.assertEqual(exported["fixture_ids"], ["truth.a", "truth.z"])

    @staticmethod
    def _computed_result(
        value: object, *, unit: str | None = None
    ) -> FunctionResult:
        return FunctionResult(
            function_id="test.unicode_result",
            function_version="0.1.0",
            status=ResultStatus.COMPUTED,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, ("R1",)),
            window=EvaluationWindow(0, 1),
            coverage=Coverage(1, 1),
            method_version="test/0.1.0",
            value=value,
            unit=unit,
        )


if __name__ == "__main__":
    unittest.main()
