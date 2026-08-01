import ast
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType
from unittest import mock

from jsonschema import Draft202012Validator

import mekai_open
from mekai_open.capture_adapter import analyze_recorded_capture
from mekai_open.contracts import ResultStatus
from mekai_open.function_registry import (
    get_function_executor,
    get_function_spec,
    list_executable_function_ids,
    list_function_specs,
)
from mekai_open.observations import (
    CaptureBoundaryKind,
    CaptureBoundaryObservation,
    CaptureDiscontinuityObservation,
    CollectorDropObservation,
    CollectorSessionObservation,
    InputMutationObservation,
    MessageDiscontinuityObservation,
    NormalizedCaptureSummary,
    NormalizedVdaObservation,
    RobotIdentity,
    SessionBoundaryKind,
)
from mekai_open.state_stream_health import (
    MAX_CONNECTION_IDENTITIES,
    MAX_SOURCE_HEALTH_COVERAGE_INTERVALS,
    MAX_SOURCE_HEALTH_DIAGNOSTICS,
    MAX_SOURCE_HEALTH_IDENTITY_CHARACTERS,
    MAX_SOURCE_HEALTH_INPUT_REFERENCES,
    MAX_SOURCE_HEALTH_INTERVALS_PER_STREAM,
    MAX_SOURCE_HEALTH_SUMMARY_DIAGNOSTICS,
    MAX_SOURCE_HEALTH_TERMINAL_DIAGNOSTICS,
    MAX_STATE_STREAMS,
    MAX_VDA_HEADER_ID,
    STATE_CARRY_FORWARD_NS,
    StateStreamHealthExecutor,
)
from mekai_open.vda_schemas import VdaMessageFamily


ROOT = Path(__file__).parents[1]
CAPTURE_FIXTURE = (
    ROOT / "fixtures" / "captures" / "state_stream_health.synthetic.capture.jsonl"
)
TRUTH_FIXTURE = ROOT / "fixtures" / "truth" / "state_stream_health.json"
RESULT_SCHEMA = ROOT / "schemas" / "function-result-0.1.schema.json"
SOURCE_ID = "synthetic-source"
INPUT_SHA256 = "1" * 64


def _diagnostic_digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _message(
    *,
    family: VdaMessageFamily = VdaMessageFamily.STATE,
    time_ns: int,
    header_id: int,
    locator: str,
    epoch: int = 1,
    topic: str = "synthetic/R-A/state",
    serial_number: str = "R-A",
    manufacturer: str = "SyntheticVendor",
    retained: bool = False,
    duplicate: bool = False,
    digest_label: str | None = None,
    connection_state: str = "ONLINE",
    source_timestamp: str = "2099-01-01T00:00:00.000Z",
    capture_codes: tuple[str, ...] = (),
) -> NormalizedVdaObservation:
    payload: dict[str, object] = {
        "headerId": header_id,
        "timestamp": source_timestamp,
        "version": "3.0.0",
        "manufacturer": manufacturer,
        "serialNumber": serial_number,
    }
    if family is VdaMessageFamily.CONNECTION:
        payload["connectionState"] = connection_state
    return NormalizedVdaObservation(
        source_id=SOURCE_ID,
        locator=locator,
        observation_time_ns=time_ns,
        continuity_epoch=epoch,
        message_family=family,
        topic=topic,
        robot_identity=RobotIdentity(manufacturer, serial_number),
        header_id=header_id,
        source_timestamp=source_timestamp,
        retained=retained,
        producer_duplicate=duplicate,
        payload_sha256=_diagnostic_digest(
            digest_label or f"{family.value}:{header_id}:{locator}"
        ),
        validated_payload=MappingProxyType(payload),
        capture_diagnostic_codes=capture_codes,
    )


def _capture_boundary(
    kind: CaptureBoundaryKind,
    time_ns: int,
    locator: str,
    *,
    declared_complete: bool | None = None,
) -> CaptureBoundaryObservation:
    return CaptureBoundaryObservation(
        source_id=SOURCE_ID,
        locator=locator,
        observation_time_ns=time_ns,
        sequence=0 if kind is CaptureBoundaryKind.START else 99,
        kind=kind,
        declared_complete=declared_complete,
    )


def _session_boundary(
    kind: SessionBoundaryKind,
    time_ns: int,
    locator: str,
    *,
    epoch: int = 1,
    capture_codes: tuple[str, ...] = (),
) -> CollectorSessionObservation:
    return CollectorSessionObservation(
        source_id=SOURCE_ID,
        locator=locator,
        observation_time_ns=time_ns,
        sequence=epoch if kind is SessionBoundaryKind.START else epoch + 1,
        kind=kind,
        producer_session_id="reused-session",
        continuity_epoch=epoch,
        capture_diagnostic_codes=capture_codes,
    )


def _regressed_coverage_observations() -> tuple[
    CaptureBoundaryObservation | CollectorSessionObservation, ...
]:
    """Return four synthetic gaps whose exact union leaves five nanoseconds."""

    return (
        _capture_boundary(CaptureBoundaryKind.START, 0, "line:1"),
        _session_boundary(SessionBoundaryKind.START, 10, "line:2", epoch=1),
        _session_boundary(SessionBoundaryKind.END, 20, "line:3", epoch=1),
        _session_boundary(SessionBoundaryKind.START, 30, "line:4", epoch=3),
        _session_boundary(
            SessionBoundaryKind.END,
            8,
            "line:5",
            epoch=3,
            capture_codes=("UTC_TIME_REGRESSION",),
        ),
        _session_boundary(SessionBoundaryKind.START, 25, "line:6", epoch=5),
        _session_boundary(SessionBoundaryKind.END, 35, "line:7", epoch=5),
        _capture_boundary(
            CaptureBoundaryKind.END,
            50,
            "line:8",
            declared_complete=True,
        ),
    )


def _summary(
    *,
    complete: bool = True,
    declared_complete: bool | None = True,
    structurally_compromised: bool = False,
    verified_unchanged: bool = True,
    physical_record_count: int = 4,
    accepted_record_count: int = 4,
    diagnostics: tuple[tuple[str, str], ...] = (),
) -> NormalizedCaptureSummary:
    return NormalizedCaptureSummary(
        source_id=SOURCE_ID,
        input_sha256=INPUT_SHA256,
        physical_record_count=physical_record_count,
        accepted_record_count=accepted_record_count,
        declared_complete=declared_complete,
        structurally_compromised=structurally_compromised,
        verified_unchanged=verified_unchanged,
        complete=complete,
        diagnostic_codes=diagnostics,
    )


def _run_complete(
    observations: tuple[object, ...],
    *,
    start_ns: int = 0,
    end_ns: int = 100_000_000_000,
    declared_complete: bool = True,
    summary_complete: bool = True,
    structurally_compromised: bool = False,
) -> object:
    executor = StateStreamHealthExecutor(SOURCE_ID)
    executor.consume(_capture_boundary(CaptureBoundaryKind.START, start_ns, "line:1"))
    executor.consume(_session_boundary(SessionBoundaryKind.START, start_ns, "line:2"))
    for observation in observations:
        executor.consume(observation)  # type: ignore[arg-type]
    executor.consume(_session_boundary(SessionBoundaryKind.END, end_ns, "line:98"))
    executor.consume(
        _capture_boundary(
            CaptureBoundaryKind.END,
            end_ns,
            "line:99",
            declared_complete=declared_complete,
        )
    )
    return executor.finish(
        _summary(
            complete=summary_complete,
            declared_complete=declared_complete,
            structurally_compromised=structurally_compromised,
            physical_record_count=len(observations) + 4,
            accepted_record_count=len(observations) + 4,
        )
    )


class StateStreamHealthTruthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.truth = json.loads(TRUTH_FIXTURE.read_text(encoding="utf-8"))
        cls.result = analyze_recorded_capture(CAPTURE_FIXTURE, SOURCE_ID)
        cls.actual = cls.result.to_dict()

    def test_independent_truth_matches_exact_result(self) -> None:
        self.assertIs(self.truth["synthetic"], True)
        self.assertTrue(self.truth["reviewer_arithmetic"])
        self.assertEqual(self.actual, self.truth["expected"])

    def test_truth_result_satisfies_function_result_schema(self) -> None:
        schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(self.actual),
            key=lambda error: tuple(str(item) for item in error.absolute_path),
        )
        self.assertEqual(errors, [])

    def test_truth_fixture_pins_message_session_and_drop_arithmetic(self) -> None:
        value = self.actual["value"]
        self.assertEqual(value["capture"]["physical_record_count"], 25)
        self.assertEqual(value["capture"]["capture_accepted_record_count"], 25)
        self.assertEqual(
            value["messages"],
            {
                "total_typed_message_records": 18,
                "function_eligible_message_count": 17,
                "capture_rejected_typed_message_count": 0,
                "vda_invalid_message_count": 1,
                "counts_by_message_family": {
                    "connection": 4,
                    "order": 1,
                    "instantActions": 1,
                    "state": 12,
                },
            },
        )
        self.assertEqual(
            value["sessions_and_drops"]["accepted_collector_session_epoch_count"],
            2,
        )
        self.assertEqual(value["sessions_and_drops"]["drop_record_count"], 1)
        self.assertEqual(value["sessions_and_drops"]["dropped_message_count"], 3)
        self.assertNotIn("drop_duration_ns", value["sessions_and_drops"])

    def test_truth_streams_remain_isolated_by_robot_topic_and_epoch(self) -> None:
        streams = self.actual["value"]["state_streams"]
        identities = {
            (
                item["robot_identity"]["serialNumber"],
                item["topic"],
                item["continuity_epoch"],
            )
            for item in streams
        }
        self.assertEqual(
            identities,
            {
                ("R-A", "synthetic/R-A/state", 1),
                ("R-A", "synthetic/R-A/state", 15),
                ("R-B", "synthetic/R-B/state", 15),
            },
        )

    def test_truth_distinguishes_header_and_duplicate_facts(self) -> None:
        stream = self.actual["value"]["state_streams"][0]
        self.assertEqual(stream["producer_duplicate_flag_count"], 1)
        self.assertEqual(stream["exact_retransmission_count"], 1)
        self.assertEqual(stream["header_gap_event_count"], 1)
        self.assertEqual(stream["missing_header_id_count"], 2)
        self.assertEqual(stream["header_regression_count"], 1)
        self.assertEqual(
            stream["same_header_different_payload_conflict_count"], 1
        )
        self.assertEqual(stream["retained_state_count"], 1)
        self.assertEqual(stream["usable_state_message_count"], 7)

    def test_truth_separates_hibernation_and_unconfirmed_silence(self) -> None:
        streams = self.actual["value"]["state_streams"]
        first = streams[0]
        self.assertEqual(
            first["confirmed_hibernation_silence_intervals"],
            [{"start_ns": 35_000_000_000, "end_ns": 65_000_000_000}],
        )
        self.assertEqual(
            first["unconfirmed_state_silence_intervals"],
            [{"start_ns": 65_000_000_000, "end_ns": 75_000_000_000}],
        )
        self.assertEqual(
            streams[1]["unconfirmed_state_silence_intervals"],
            [{"start_ns": 130_000_000_000, "end_ns": 150_000_000_000}],
        )
        self.assertEqual(
            streams[2]["unconfirmed_state_silence_intervals"],
            [{"start_ns": 125_000_000_000, "end_ns": 150_000_000_000}],
        )

    def test_truth_coverage_uses_only_known_outside_session_time(self) -> None:
        self.assertEqual(self.actual["window"], {"start_ns": 0, "end_ns": 160_000_000_000})
        self.assertEqual(self.actual["coverage"]["eligible_duration_ns"], 160_000_000_000)
        self.assertEqual(self.actual["coverage"]["observed_duration_ns"], 140_000_000_000)
        self.assertEqual(self.actual["coverage"]["ratio"], 0.875)
        self.assertEqual(len(self.actual["coverage"]["missing_intervals"]), 2)
        self.assertEqual(
            self.actual["coverage"]["known_missing_interval_count"], 2
        )
        self.assertIs(
            self.actual["coverage"]["missing_interval_details_truncated"],
            False,
        )

    def test_repeated_runs_are_deterministic(self) -> None:
        repeated = analyze_recorded_capture(CAPTURE_FIXTURE, SOURCE_ID)
        self.assertEqual(repeated.to_json(), self.result.to_json())


class StateStreamHealthExecutorTests(unittest.TestCase):
    def test_specification_keeps_its_compiled_executor_binding(self) -> None:
        qualified_id = "vda.state_stream_health@0.1.0"
        spec = get_function_spec(qualified_id)
        self.assertEqual(spec.fixture_ids, ("truth.state_stream_health",))
        self.assertEqual(
            spec.required_message_families, ("connection", "state")
        )
        self.assertIn(qualified_id, list_executable_function_ids())
        self.assertIsInstance(
            get_function_executor(qualified_id, source_id=SOURCE_ID),
            StateStreamHealthExecutor,
        )
        self.assertEqual(
            set(list_executable_function_ids()),
            {spec.qualified_id for spec in list_function_specs()},
        )
        self.assertGreater(len(list_function_specs()), 1)

    def test_unknown_executor_lookup_fails_closed(self) -> None:
        with self.assertRaises(KeyError):
            get_function_executor("vda.unknown@0.1.0", source_id=SOURCE_ID)

    def test_core_does_not_import_capture_mqtt_or_ros(self) -> None:
        path = ROOT / "src" / "mekai_open" / "state_stream_health.py"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        combined = " ".join(sorted(imports)).lower()
        self.assertNotIn("capture_jsonl", combined)
        self.assertNotIn("mqtt", combined)
        self.assertNotIn("ros", combined)

    def test_executor_binding_has_no_dynamic_loading_or_code_execution(self) -> None:
        paths = (
            ROOT / "src" / "mekai_open" / "function_registry.py",
            ROOT / "src" / "mekai_open" / "state_stream_health.py",
            ROOT / "src" / "mekai_open" / "capture_adapter.py",
        )
        violations: list[str] = []
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "eval",
                    "exec",
                    "__import__",
                }:
                    violations.append(f"{path.name}:{node.func.id}")
                if isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "import_module",
                    "entry_points",
                    "publish",
                }:
                    violations.append(f"{path.name}:{node.func.attr}")
        self.assertEqual(violations, [])

    def test_uint32_header_boundaries_and_out_of_range_diagnostics(self) -> None:
        result = _run_complete(
            (
                _message(time_ns=0, header_id=0, locator="line:3"),
                _message(
                    time_ns=1,
                    header_id=MAX_VDA_HEADER_ID,
                    locator="line:4",
                    topic="synthetic/R-A/state-max",
                ),
                _message(
                    time_ns=2,
                    header_id=-1,
                    locator="line:5",
                    topic="synthetic/R-A/state-negative",
                ),
                _message(
                    time_ns=3,
                    header_id=MAX_VDA_HEADER_ID + 1,
                    locator="line:6",
                    topic="synthetic/R-A/state-over",
                ),
            ),
            end_ns=10,
        )
        streams = result.to_dict()["value"]["state_streams"]
        usable = {item["topic"]: item["usable_state_message_count"] for item in streams}
        self.assertEqual(usable["synthetic/R-A/state"], 1)
        self.assertEqual(usable["synthetic/R-A/state-max"], 1)
        self.assertEqual(usable["synthetic/R-A/state-negative"], 0)
        self.assertEqual(usable["synthetic/R-A/state-over"], 0)
        self.assertIn("HEADER_OUT_OF_RANGE@line:5", result.diagnostics)
        self.assertIn("HEADER_OUT_OF_RANGE@line:6", result.diagnostics)

    def test_connection_header_range_gates_hibernation_state(self) -> None:
        cases = (
            (-1, False),
            (0, True),
            (MAX_VDA_HEADER_ID, True),
            (MAX_VDA_HEADER_ID + 1, False),
        )
        for header_id, accepted_for_state in cases:
            with self.subTest(header_id=header_id):
                result = _run_complete(
                    (
                        _message(time_ns=0, header_id=0, locator="line:3"),
                        _message(
                            family=VdaMessageFamily.CONNECTION,
                            time_ns=10_000_000_000,
                            header_id=header_id,
                            locator="line:4",
                            topic="synthetic/R-A/connection",
                            connection_state="HIBERNATING",
                        ),
                    ),
                    end_ns=50_000_000_000,
                )
                stream = result.to_dict()["value"]["state_streams"][0]
                self.assertEqual(
                    result.to_dict()["value"]["messages"][
                        "function_eligible_message_count"
                    ],
                    2,
                )
                self.assertEqual(
                    result.to_dict()["value"]["messages"][
                        "counts_by_message_family"
                    ]["connection"],
                    1,
                )
                if accepted_for_state:
                    self.assertEqual(
                        stream["confirmed_hibernation_silence_intervals"],
                        [
                            {
                                "start_ns": 10_000_000_000,
                                "end_ns": 50_000_000_000,
                            }
                        ],
                    )
                    self.assertEqual(
                        stream["unconfirmed_state_silence_intervals"], []
                    )
                    self.assertNotIn(
                        "HEADER_OUT_OF_RANGE@line:4", result.diagnostics
                    )
                    self.assertEqual(result.status, ResultStatus.COMPUTED)
                else:
                    self.assertEqual(
                        stream["confirmed_hibernation_silence_intervals"], []
                    )
                    self.assertEqual(
                        stream["unconfirmed_state_silence_intervals"],
                        [
                            {
                                "start_ns": 30_000_000_000,
                                "end_ns": 50_000_000_000,
                            }
                        ],
                    )
                    self.assertIn(
                        "HEADER_OUT_OF_RANGE@line:4", result.diagnostics
                    )
                    self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_out_of_range_connection_cannot_end_confirmed_hibernation(self) -> None:
        result = _run_complete(
            (
                _message(time_ns=0, header_id=0, locator="line:3"),
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=10,
                    header_id=0,
                    locator="line:4",
                    topic="synthetic/R-A/connection",
                    connection_state="HIBERNATING",
                ),
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=20,
                    header_id=MAX_VDA_HEADER_ID + 1,
                    locator="line:5",
                    topic="synthetic/R-A/connection",
                    connection_state="ONLINE",
                ),
            ),
            end_ns=50,
        )
        stream = result.to_dict()["value"]["state_streams"][0]
        self.assertEqual(
            stream["confirmed_hibernation_silence_intervals"],
            [{"start_ns": 10, "end_ns": 50}],
        )
        self.assertEqual(stream["unconfirmed_state_silence_intervals"], [])
        self.assertIn("HEADER_OUT_OF_RANGE@line:5", result.diagnostics)
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_robot_and_topic_dimensions_isolate_stream_baselines(self) -> None:
        result = _run_complete(
            (
                _message(
                    time_ns=1,
                    header_id=10,
                    locator="line:3",
                    topic="synthetic/shared/state",
                    serial_number="R-A",
                ),
                _message(
                    time_ns=2,
                    header_id=20,
                    locator="line:4",
                    topic="synthetic/shared/state",
                    serial_number="R-B",
                ),
                _message(
                    time_ns=3,
                    header_id=30,
                    locator="line:5",
                    topic="synthetic/alternate/state",
                    serial_number="R-A",
                ),
            ),
            end_ns=10,
        )
        streams = result.to_dict()["value"]["state_streams"]
        identities = {
            (
                item["robot_identity"]["serialNumber"],
                item["topic"],
                item["usable_state_message_count"],
            )
            for item in streams
        }
        self.assertEqual(
            identities,
            {
                ("R-A", "synthetic/shared/state", 1),
                ("R-B", "synthetic/shared/state", 1),
                ("R-A", "synthetic/alternate/state", 1),
            },
        )

    def test_duplicate_facts_do_not_make_a_complete_calculation_partial(self) -> None:
        result = _run_complete(
            (
                _message(
                    time_ns=1,
                    header_id=1,
                    locator="line:3",
                    digest_label="same",
                ),
                _message(
                    time_ns=2,
                    header_id=1,
                    locator="line:4",
                    digest_label="same",
                    duplicate=True,
                ),
                _message(
                    time_ns=3,
                    header_id=2,
                    locator="line:5",
                    duplicate=True,
                ),
            ),
            end_ns=10,
        )
        stream = result.to_dict()["value"]["state_streams"][0]
        self.assertEqual(stream["producer_duplicate_flag_count"], 2)
        self.assertEqual(stream["exact_retransmission_count"], 1)
        self.assertEqual(result.status, ResultStatus.COMPUTED)

    def test_retained_connection_applies_but_retained_state_does_not_advance(self) -> None:
        result = _run_complete(
            (
                _message(time_ns=0, header_id=1, locator="line:3"),
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=10,
                    header_id=1,
                    locator="line:4",
                    topic="synthetic/R-A/connection",
                    connection_state="HIBERNATING",
                ),
                _message(
                    time_ns=15,
                    header_id=2,
                    locator="line:5",
                    retained=True,
                ),
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=20,
                    header_id=2,
                    locator="line:6",
                    topic="synthetic/R-A/connection",
                    connection_state="ONLINE",
                    retained=True,
                ),
                _message(time_ns=25, header_id=2, locator="line:7"),
            ),
            end_ns=30,
        )
        stream = result.to_dict()["value"]["state_streams"][0]
        self.assertEqual(stream["retained_state_count"], 1)
        self.assertEqual(stream["usable_state_message_count"], 2)
        self.assertEqual(
            stream["confirmed_hibernation_silence_intervals"],
            [{"start_ns": 10, "end_ns": 20}],
        )
        self.assertEqual(stream["unconfirmed_state_silence_intervals"], [])
        self.assertEqual(result.status, ResultStatus.COMPUTED)

    def test_drop_count_does_not_create_a_duration(self) -> None:
        drop = CollectorDropObservation(
            source_id=SOURCE_ID,
            locator="line:3",
            observation_time_ns=10,
            sequence=2,
            continuity_epoch=1,
            producer_session_id="reused-session",
            drop_count=7,
            drop_reason="synthetic_drop",
        )
        result = _run_complete((drop,), end_ns=100)
        value = result.to_dict()["value"]["sessions_and_drops"]
        self.assertEqual(value["drop_record_count"], 1)
        self.assertEqual(value["dropped_message_count"], 7)
        self.assertEqual(result.coverage.observed_duration_ns, 100)
        self.assertEqual(result.coverage.missing_intervals, ())
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_rejected_and_invalid_messages_never_create_transitions(self) -> None:
        rejected = MessageDiscontinuityObservation(
            source_id=SOURCE_ID,
            locator="line:3",
            observation_time_ns=1,
            continuity_epoch=None,
            message_family=VdaMessageFamily.STATE,
            topic="synthetic/R-A/state",
            payload_sha256="2" * 64,
            capture_accepted=False,
            vda_valid=True,
            capture_diagnostic_codes=("SESSION_ID_MISMATCH",),
            vda_diagnostic_codes=(),
        )
        invalid = MessageDiscontinuityObservation(
            source_id=SOURCE_ID,
            locator="line:4",
            observation_time_ns=2,
            continuity_epoch=1,
            message_family=VdaMessageFamily.STATE,
            topic="synthetic/R-A/state",
            payload_sha256="3" * 64,
            capture_accepted=True,
            vda_valid=False,
            capture_diagnostic_codes=(),
            vda_diagnostic_codes=("SCHEMA_VIOLATION",),
        )
        valid = _message(time_ns=3, header_id=9, locator="line:5")
        result = _run_complete((rejected, invalid, valid), end_ns=10)
        value = result.to_dict()["value"]
        self.assertEqual(value["messages"]["total_typed_message_records"], 3)
        self.assertEqual(value["messages"]["function_eligible_message_count"], 1)
        self.assertEqual(
            value["messages"]["capture_rejected_typed_message_count"], 1
        )
        self.assertEqual(value["messages"]["vda_invalid_message_count"], 1)
        self.assertEqual(value["state_streams"][0]["usable_state_message_count"], 1)

    def test_observation_clock_is_used_and_utc_regression_is_not_sorted(self) -> None:
        first = _message(
            time_ns=100,
            header_id=0,
            locator="line:3",
            source_timestamp="2099-01-01T23:59:59.000Z",
        )
        second = _message(
            time_ns=50,
            header_id=1,
            locator="line:4",
            source_timestamp="2000-01-01T00:00:00.000Z",
            capture_codes=("UTC_TIME_REGRESSION",),
        )
        result = _run_complete((first, second), end_ns=200)
        stream = result.to_dict()["value"]["state_streams"][0]
        self.assertEqual(stream["first_observation_time_ns"], 100)
        self.assertEqual(stream["last_observation_time_ns"], 50)
        self.assertEqual(stream["observed_inter_arrival_count"], 0)
        self.assertIn("UTC_TIME_REGRESSION@line:4", result.diagnostics)

    def test_undefined_and_zero_length_windows_are_not_computable(self) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        executor.consume(_capture_boundary(CaptureBoundaryKind.START, 10, "line:1"))
        missing_end = executor.finish(
            _summary(
                complete=False,
                declared_complete=None,
                structurally_compromised=True,
                physical_record_count=1,
                accepted_record_count=1,
            )
        )
        self.assertEqual(missing_end.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIsNone(missing_end.window)
        self.assertIn("WINDOW_UNDEFINED", missing_end.diagnostics)

        zero = StateStreamHealthExecutor(SOURCE_ID)
        zero.consume(_capture_boundary(CaptureBoundaryKind.START, 10, "line:1"))
        zero.consume(
            _capture_boundary(
                CaptureBoundaryKind.END,
                10,
                "line:2",
                declared_complete=True,
            )
        )
        zero_result = zero.finish(_summary(physical_record_count=2, accepted_record_count=2))
        self.assertEqual(zero_result.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIsNone(zero_result.window)
        self.assertIn("WINDOW_UNDEFINED", zero_result.diagnostics)
        schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            list(Draft202012Validator(schema).iter_errors(zero_result.to_dict())),
            [],
        )

    def test_declared_incomplete_capture_is_partial_when_window_is_meaningful(self) -> None:
        result = _run_complete(
            (_message(time_ns=1, header_id=0, locator="line:3"),),
            end_ns=10,
            declared_complete=False,
            summary_complete=False,
        )
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertEqual(result.window.start_ns, 0)
        self.assertEqual(result.window.end_ns, 10)
        self.assertIn("CAPTURE_INCOMPLETE@line:99", result.diagnostics)

    def test_input_mutation_is_not_computable_and_has_no_fabricated_window(self) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        executor.consume(InputMutationObservation(SOURCE_ID))
        result = executor.finish(
            _summary(
                physical_record_count=MAX_SOURCE_HEALTH_DIAGNOSTICS,
                accepted_record_count=0,
            )
        )
        self.assertEqual(result.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIsNone(result.window)
        self.assertEqual(result.coverage.eligible_duration_ns, 0)
        self.assertEqual(result.diagnostics, ("INPUT_CHANGED",))

    def test_input_changed_survives_a_full_event_diagnostic_budget(self) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        for index in range(MAX_SOURCE_HEALTH_DIAGNOSTICS):
            executor.consume(
                CaptureDiscontinuityObservation(
                    source_id=SOURCE_ID,
                    locator=f"line:{index + 1}",
                    observation_time_ns=None,
                    record_kind=None,
                    diagnostic_codes=("MALFORMED_JSON",),
                )
            )
        executor.consume(InputMutationObservation(SOURCE_ID))
        result = executor.finish(None)

        self.assertEqual(result.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIn("INPUT_CHANGED", result.diagnostics)
        self.assertIsNone(result.value)
        self.assertIsNone(result.window)
        self.assertEqual(result.coverage.eligible_duration_ns, 0)
        self.assertEqual(result.coverage.observed_duration_ns, 0)
        self.assertEqual(result.input_references, ())

    def test_window_undefined_survives_a_full_event_diagnostic_budget(self) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        for index in range(MAX_SOURCE_HEALTH_DIAGNOSTICS):
            executor.consume(
                CaptureDiscontinuityObservation(
                    source_id=SOURCE_ID,
                    locator=f"line:{index + 1}",
                    observation_time_ns=None,
                    record_kind=None,
                    diagnostic_codes=("MALFORMED_JSON",),
                )
            )
        result = executor.finish(
            _summary(
                physical_record_count=MAX_SOURCE_HEALTH_DIAGNOSTICS,
                accepted_record_count=0,
            )
        )

        self.assertEqual(result.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIn("WINDOW_UNDEFINED", result.diagnostics)
        self.assertIsNone(result.window)
        self.assertEqual(result.coverage.eligible_duration_ns, 0)
        self.assertEqual(result.coverage.observed_duration_ns, 0)

    def test_capture_discontinuity_is_reported_without_becoming_a_message(self) -> None:
        discontinuity = CaptureDiscontinuityObservation(
            source_id=SOURCE_ID,
            locator="line:3",
            observation_time_ns=None,
            record_kind=None,
            diagnostic_codes=("MALFORMED_JSON",),
        )
        result = _run_complete(
            (discontinuity,),
            end_ns=10,
            summary_complete=False,
            structurally_compromised=True,
        )
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertEqual(
            result.to_dict()["value"]["messages"]["total_typed_message_records"],
            0,
        )
        self.assertIn("CAPTURE_RECORD_INVALID@line:3", result.diagnostics)

    def test_normalized_result_value_is_immutable(self) -> None:
        result = _run_complete(
            (_message(time_ns=1, header_id=0, locator="line:3"),),
            end_ns=10,
        )
        with self.assertRaises(TypeError):
            result.value["source_id"] = "changed"  # type: ignore[index]
        with self.assertRaises(AttributeError):
            result.value["state_streams"].append({})  # type: ignore[union-attr]

    def test_named_resource_limits_are_positive_and_finite(self) -> None:
        limits = (
            MAX_STATE_STREAMS,
            MAX_CONNECTION_IDENTITIES,
            MAX_SOURCE_HEALTH_DIAGNOSTICS,
            MAX_SOURCE_HEALTH_INPUT_REFERENCES,
            MAX_SOURCE_HEALTH_INTERVALS_PER_STREAM,
            MAX_SOURCE_HEALTH_COVERAGE_INTERVALS,
            MAX_SOURCE_HEALTH_IDENTITY_CHARACTERS,
            MAX_SOURCE_HEALTH_SUMMARY_DIAGNOSTICS,
            MAX_SOURCE_HEALTH_TERMINAL_DIAGNOSTICS,
        )
        self.assertTrue(all(isinstance(value, int) and value > 0 for value in limits))
        self.assertEqual(STATE_CARRY_FORWARD_NS, 30_000_000_000)

    def test_oversized_stream_identity_is_not_retained_or_truncated(self) -> None:
        manufacturer = "M" * (MAX_SOURCE_HEALTH_IDENTITY_CHARACTERS + 1)
        result = _run_complete(
            (
                _message(
                    time_ns=1,
                    header_id=0,
                    locator="line:3",
                    manufacturer=manufacturer,
                ),
            ),
            end_ns=10,
        )
        self.assertEqual(result.to_dict()["value"]["state_streams"], [])
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertIn("RESOURCE_LIMIT@line:3", result.diagnostics)

    def test_stream_and_reference_limits_fail_partial_without_unbounded_growth(self) -> None:
        messages = (
            _message(time_ns=1, header_id=0, locator="line:3", topic="synthetic/a"),
            _message(time_ns=2, header_id=0, locator="line:4", topic="synthetic/b"),
        )
        with mock.patch("mekai_open.state_stream_health.MAX_STATE_STREAMS", 1), mock.patch(
            "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_INPUT_REFERENCES", 1
        ):
            result = _run_complete(messages, end_ns=10)
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertEqual(len(result.to_dict()["value"]["state_streams"]), 1)
        self.assertEqual(len(result.input_references), 1)
        self.assertTrue(
            any(item.startswith("RESOURCE_LIMIT@") for item in result.diagnostics)
        )

    def test_connection_identity_collection_is_bounded_and_diagnosed(self) -> None:
        observations = (
            _message(
                family=VdaMessageFamily.CONNECTION,
                time_ns=1,
                header_id=0,
                locator="line:3",
                topic="synthetic/R-A/connection",
                serial_number="R-A",
            ),
            _message(
                family=VdaMessageFamily.CONNECTION,
                time_ns=2,
                header_id=0,
                locator="line:4",
                topic="synthetic/R-B/connection",
                serial_number="R-B",
            ),
        )
        with mock.patch("mekai_open.state_stream_health.MAX_CONNECTION_IDENTITIES", 1):
            result = _run_complete(observations, end_ns=10)
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertIn("RESOURCE_LIMIT@line:4", result.diagnostics)

    def test_diagnostic_collection_is_bounded_with_truncation_marker(self) -> None:
        observations = (
            _message(
                time_ns=1,
                header_id=0,
                locator="line:3",
                retained=True,
            ),
            _message(
                time_ns=2,
                header_id=-1,
                locator="line:4",
            ),
        )
        with mock.patch("mekai_open.state_stream_health.MAX_SOURCE_HEALTH_DIAGNOSTICS", 1):
            result = _run_complete(observations, end_ns=10)
        self.assertEqual(len(result.diagnostics), 2)
        self.assertEqual(result.diagnostics[-1], "DIAGNOSTICS_TRUNCATED")
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_stream_interval_collection_is_bounded_and_diagnosed(self) -> None:
        observations = (
            _message(time_ns=0, header_id=0, locator="line:3"),
            _message(
                time_ns=40_000_000_000,
                header_id=1,
                locator="line:4",
            ),
            _message(
                time_ns=80_000_000_000,
                header_id=2,
                locator="line:5",
            ),
        )
        with mock.patch(
            "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_INTERVALS_PER_STREAM",
            1,
        ):
            result = _run_complete(observations, end_ns=90_000_000_000)
        stream = result.to_dict()["value"]["state_streams"][0]
        self.assertEqual(len(stream["unconfirmed_state_silence_intervals"]), 1)
        self.assertIn("RESOURCE_LIMIT@line:5", result.diagnostics)
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_coverage_interval_collection_is_bounded_and_diagnosed(self) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        observations = (
            _capture_boundary(CaptureBoundaryKind.START, 0, "line:1"),
            _session_boundary(SessionBoundaryKind.START, 10, "line:2", epoch=1),
            _session_boundary(SessionBoundaryKind.END, 20, "line:3", epoch=1),
            _session_boundary(SessionBoundaryKind.START, 30, "line:4", epoch=4),
            _session_boundary(SessionBoundaryKind.END, 40, "line:5", epoch=4),
            _capture_boundary(
                CaptureBoundaryKind.END,
                50,
                "line:6",
                declared_complete=True,
            ),
        )
        with mock.patch(
            "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_COVERAGE_INTERVALS",
            1,
        ):
            for observation in observations:
                executor.consume(observation)
            result = executor.finish(
                _summary(physical_record_count=6, accepted_record_count=6)
            )
        self.assertLessEqual(len(result.coverage.missing_intervals), 1)
        self.assertGreater(result.coverage.known_missing_interval_count, 1)
        self.assertIs(result.coverage.missing_interval_details_truncated, True)
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertIn(
            "COVERAGE_INTERVAL_DETAILS_TRUNCATED",
            result.diagnostics,
        )

    def test_regression_after_truncation_overlapping_retained_and_omitted_detail(
        self,
    ) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        with mock.patch(
            "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_COVERAGE_INTERVALS",
            1,
        ):
            for observation in _regressed_coverage_observations():
                executor.consume(observation)
            result = executor.finish(
                _summary(physical_record_count=8, accepted_record_count=8)
            )

        self.assertEqual(result.coverage.eligible_duration_ns, 50)
        self.assertIsNone(result.coverage.observed_duration_ns)
        self.assertIsNone(result.coverage.ratio)
        self.assertEqual(
            [item.to_dict() for item in result.coverage.missing_intervals],
            [
                {
                    "start_ns": 0,
                    "end_ns": 10,
                    "reason": "COLLECTOR_SESSION_GAP",
                }
            ],
        )
        self.assertEqual(result.coverage.known_missing_interval_count, 4)
        self.assertIs(result.coverage.missing_interval_details_truncated, True)
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertIn("UTC_TIME_REGRESSION@line:5", result.diagnostics)
        self.assertIn("COVERAGE_DURATION_UNAVAILABLE", result.diagnostics)
        schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors(result.to_dict())), [])
        invalid_computed = result.to_dict()
        invalid_computed["status"] = "COMPUTED"
        self.assertTrue(list(validator.iter_errors(invalid_computed)))
        invalid_complete_detail = result.to_dict()
        invalid_complete_detail["coverage"][
            "missing_interval_details_truncated"
        ] = False
        self.assertTrue(list(validator.iter_errors(invalid_complete_detail)))
        invalid_ratio = result.to_dict()
        invalid_ratio["coverage"]["ratio"] = 0.1
        self.assertTrue(list(validator.iter_errors(invalid_ratio)))

    def test_regressed_gaps_remain_exact_when_all_coordinates_are_retained(
        self,
    ) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        for observation in _regressed_coverage_observations():
            executor.consume(observation)
        result = executor.finish(
            _summary(physical_record_count=8, accepted_record_count=8)
        )

        self.assertEqual(result.coverage.observed_duration_ns, 5)
        self.assertEqual(result.coverage.ratio, 0.1)
        self.assertEqual(result.coverage.known_missing_interval_count, 4)
        self.assertIs(result.coverage.missing_interval_details_truncated, False)
        self.assertNotIn("COVERAGE_DURATION_UNAVAILABLE", result.diagnostics)
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_regression_before_later_detail_truncation_is_not_forgotten(
        self,
    ) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        with mock.patch(
            "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_COVERAGE_INTERVALS",
            3,
        ):
            for observation in _regressed_coverage_observations():
                executor.consume(observation)
            result = executor.finish(
                _summary(physical_record_count=8, accepted_record_count=8)
            )

        self.assertIsNone(result.coverage.observed_duration_ns)
        self.assertEqual(len(result.coverage.missing_intervals), 1)
        self.assertEqual(result.coverage.known_missing_interval_count, 4)
        self.assertIn("COVERAGE_DURATION_UNAVAILABLE", result.diagnostics)

    def test_multiple_regressed_gap_starts_keep_truncated_coverage_unavailable(
        self,
    ) -> None:
        observations = (
            _capture_boundary(CaptureBoundaryKind.START, 0, "line:1"),
            _session_boundary(SessionBoundaryKind.START, 10, "line:2", epoch=1),
            _session_boundary(SessionBoundaryKind.END, 20, "line:3", epoch=1),
            _session_boundary(SessionBoundaryKind.START, 30, "line:4", epoch=3),
            _session_boundary(
                SessionBoundaryKind.END,
                8,
                "line:5",
                epoch=3,
                capture_codes=("UTC_TIME_REGRESSION",),
            ),
            _session_boundary(SessionBoundaryKind.START, 25, "line:6", epoch=5),
            _session_boundary(
                SessionBoundaryKind.END,
                5,
                "line:7",
                epoch=5,
                capture_codes=("UTC_TIME_REGRESSION",),
            ),
            _session_boundary(SessionBoundaryKind.START, 28, "line:8", epoch=7),
            _session_boundary(SessionBoundaryKind.END, 35, "line:9", epoch=7),
            _capture_boundary(
                CaptureBoundaryKind.END,
                50,
                "line:10",
                declared_complete=True,
            ),
        )
        executor = StateStreamHealthExecutor(SOURCE_ID)
        with mock.patch(
            "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_COVERAGE_INTERVALS",
            1,
        ):
            for observation in observations:
                executor.consume(observation)
            result = executor.finish(
                _summary(physical_record_count=10, accepted_record_count=10)
            )

        self.assertIsNone(result.coverage.observed_duration_ns)
        self.assertEqual(result.coverage.known_missing_interval_count, 5)
        self.assertIn("COVERAGE_DURATION_UNAVAILABLE", result.diagnostics)

    def test_truncated_gap_outside_window_does_not_create_clipped_approximation(
        self,
    ) -> None:
        observations = (
            _capture_boundary(CaptureBoundaryKind.START, 10, "line:1"),
            _session_boundary(SessionBoundaryKind.START, 10, "line:2", epoch=1),
            _session_boundary(
                SessionBoundaryKind.END,
                0,
                "line:3",
                epoch=1,
                capture_codes=("UTC_TIME_REGRESSION",),
            ),
            _session_boundary(SessionBoundaryKind.START, 20, "line:4", epoch=3),
            _session_boundary(SessionBoundaryKind.END, 30, "line:5", epoch=3),
            _capture_boundary(
                CaptureBoundaryKind.END,
                50,
                "line:6",
                declared_complete=True,
            ),
        )
        for limit, expected_observed in ((1, None), (2, 10)):
            with self.subTest(limit=limit):
                executor = StateStreamHealthExecutor(SOURCE_ID)
                with mock.patch(
                    "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_COVERAGE_INTERVALS",
                    limit,
                ):
                    for observation in observations:
                        executor.consume(observation)
                    result = executor.finish(
                        _summary(physical_record_count=6, accepted_record_count=6)
                    )
                self.assertEqual(
                    result.coverage.observed_duration_ns,
                    expected_observed,
                )
                self.assertEqual(
                    "COVERAGE_DURATION_UNAVAILABLE" in result.diagnostics,
                    limit == 1,
                )

    def test_capture_reader_regression_and_truncation_make_coverage_unavailable(
        self,
    ) -> None:
        records = (
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "capture_start",
                "sequence": 0,
                "receive_time_ns": 0,
            },
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "session_start",
                "sequence": 1,
                "receive_time_ns": 10,
                "collector_session_id": "synthetic-session",
            },
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "session_end",
                "sequence": 2,
                "receive_time_ns": 20,
                "collector_session_id": "synthetic-session",
            },
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "session_start",
                "sequence": 3,
                "receive_time_ns": 30,
                "collector_session_id": "synthetic-session",
            },
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "session_end",
                "sequence": 4,
                "receive_time_ns": 8,
                "collector_session_id": "synthetic-session",
            },
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "session_start",
                "sequence": 5,
                "receive_time_ns": 25,
                "collector_session_id": "synthetic-session",
            },
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "session_end",
                "sequence": 6,
                "receive_time_ns": 35,
                "collector_session_id": "synthetic-session",
            },
            {
                "schema": "mekai.capture_record/0.1",
                "kind": "capture_end",
                "sequence": 7,
                "receive_time_ns": 50,
                "complete": True,
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "regressed.synthetic.capture.jsonl"
            path.write_text(
                "".join(
                    json.dumps(record, separators=(",", ":")) + "\n"
                    for record in records
                ),
                encoding="utf-8",
            )
            with mock.patch(
                "mekai_open.state_stream_health.MAX_SOURCE_HEALTH_COVERAGE_INTERVALS",
                1,
            ):
                result = analyze_recorded_capture(path, SOURCE_ID)

        self.assertIsNone(result.coverage.observed_duration_ns)
        self.assertIsNone(result.coverage.ratio)
        self.assertEqual(result.coverage.known_missing_interval_count, 4)
        self.assertIs(result.coverage.missing_interval_details_truncated, True)
        self.assertIn("UTC_TIME_REGRESSION@line:5", result.diagnostics)
        self.assertIn("COVERAGE_DURATION_UNAVAILABLE", result.diagnostics)
        self.assertEqual(
            result.to_dict()["value"]["capture"]["physical_record_count"],
            8,
        )
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_real_coverage_limit_keeps_all_known_gap_duration(self) -> None:
        executor = StateStreamHealthExecutor(SOURCE_ID)
        executor.consume(
            CaptureBoundaryObservation(
                source_id=SOURCE_ID,
                locator="line:1",
                observation_time_ns=0,
                sequence=0,
                kind=CaptureBoundaryKind.START,
                declared_complete=None,
            )
        )
        for index in range(MAX_SOURCE_HEALTH_COVERAGE_INTERVALS):
            start_sequence = 1 + (2 * index)
            end_sequence = start_sequence + 1
            executor.consume(
                CollectorSessionObservation(
                    source_id=SOURCE_ID,
                    locator=f"line:{start_sequence + 1}",
                    observation_time_ns=1 + (2 * index),
                    sequence=start_sequence,
                    kind=SessionBoundaryKind.START,
                    producer_session_id="reused-session",
                    continuity_epoch=start_sequence,
                )
            )
            executor.consume(
                CollectorSessionObservation(
                    source_id=SOURCE_ID,
                    locator=f"line:{end_sequence + 1}",
                    observation_time_ns=2 + (2 * index),
                    sequence=end_sequence,
                    kind=SessionBoundaryKind.END,
                    producer_session_id="reused-session",
                    continuity_epoch=start_sequence,
                )
            )
        window_end_ns = 1_000_000_000_512
        executor.consume(
            CaptureBoundaryObservation(
                source_id=SOURCE_ID,
                locator="line:514",
                observation_time_ns=window_end_ns,
                sequence=513,
                kind=CaptureBoundaryKind.END,
                declared_complete=True,
            )
        )
        result = executor.finish(
            _summary(physical_record_count=514, accepted_record_count=514)
        )

        self.assertEqual(result.coverage.eligible_duration_ns, window_end_ns)
        self.assertEqual(result.coverage.observed_duration_ns, 256)
        self.assertEqual(
            result.coverage.ratio,
            256 / window_end_ns,
        )
        self.assertEqual(
            len(result.coverage.missing_intervals),
            MAX_SOURCE_HEALTH_COVERAGE_INTERVALS,
        )
        self.assertEqual(result.coverage.known_missing_interval_count, 257)
        self.assertIs(result.coverage.missing_interval_details_truncated, True)
        self.assertIn(
            "COVERAGE_INTERVAL_DETAILS_TRUNCATED",
            result.diagnostics,
        )
        self.assertIn("DIAGNOSTICS_TRUNCATED", result.diagnostics)
        self.assertEqual(result.status, ResultStatus.PARTIAL)

        schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        self.assertEqual(list(validator.iter_errors(result.to_dict())), [])
        invalid_status = result.to_dict()
        invalid_status["status"] = "COMPUTED"
        self.assertTrue(list(validator.iter_errors(invalid_status)))

    def test_no_new_top_level_export_or_cli_surface_is_introduced(self) -> None:
        self.assertNotIn("analyze_recorded_capture", mekai_open.__all__)
        self.assertNotIn("StateStreamHealthExecutor", mekai_open.__all__)
        self.assertNotIn("NormalizedVdaObservation", mekai_open.__all__)


if __name__ == "__main__":
    unittest.main()
