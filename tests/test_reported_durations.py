import ast
import base64
import hashlib
import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType
from unittest import mock

from jsonschema import Draft202012Validator

import mekai_open
from mekai_open.capture_adapter import (
    normalize_capture_item,
    normalize_capture_summary,
)
from mekai_open.capture_jsonl import CaptureReader
from mekai_open.contracts import ResultStatus
from mekai_open.function_registry import (
    get_function_executor,
    get_function_spec,
    list_executable_function_ids,
)
from mekai_open.observations import (
    MAX_ROBOT_TARGET_IDENTITY_CHARACTERS,
    MAX_ROBOT_TARGET_SUBJECT_ID_CHARACTERS,
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
    RobotTarget,
    SessionBoundaryKind,
)
from mekai_open.recorded_functions import MAX_VDA_HEADER_ID, STATE_CARRY_FORWARD_NS
from mekai_open.reported_durations import (
    MAX_REPORTED_DURATION_DIAGNOSTICS,
    MAX_REPORTED_DURATION_INPUT_REFERENCES,
    MAX_REPORTED_DURATION_INTERVAL_DETAILS,
    REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
    REPORTED_CHARGING_DURATION_QUALIFIED_ID,
    REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
    REPORTED_DRIVING_DURATION_QUALIFIED_ID,
    REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID,
    REPORTED_PAUSED_DURATION_QUALIFIED_ID,
    REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID,
    ReportedBatteryStateOfChargeExecutor,
    ReportedConnectionStateDurationExecutor,
    ReportedDrivingDurationExecutor,
    ReportedStateDurationExecutor,
)
from mekai_open.state_stream_health import STATE_STREAM_HEALTH_QUALIFIED_ID
from mekai_open.vda_schemas import VdaMessageFamily


ROOT = Path(__file__).parents[1]
CAPTURE_ROOT = ROOT / "fixtures" / "captures"
TRUTH_ROOT = ROOT / "fixtures" / "truth"
RESULT_SCHEMA = ROOT / "schemas" / "function-result-0.1.schema.json"
SOURCE_ID = "reported-duration-source"
INPUT_SHA256 = "a" * 64
NANOSECONDS = 1_000_000_000
TARGET = RobotTarget(
    "R1",
    RobotIdentity("SyntheticVendor", "R-A"),
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _capture_boundary(
    kind: CaptureBoundaryKind,
    time_ns: int,
    locator: str,
    *,
    declared_complete: bool | None = None,
    capture_codes: tuple[str, ...] = (),
) -> CaptureBoundaryObservation:
    return CaptureBoundaryObservation(
        source_id=SOURCE_ID,
        locator=locator,
        observation_time_ns=time_ns,
        sequence=0 if kind is CaptureBoundaryKind.START else 999,
        kind=kind,
        declared_complete=declared_complete,
        capture_diagnostic_codes=capture_codes,
    )


def _session_boundary(
    kind: SessionBoundaryKind,
    time_ns: int,
    locator: str,
    *,
    epoch: int = 1,
    producer_session_id: str = "session",
) -> CollectorSessionObservation:
    return CollectorSessionObservation(
        source_id=SOURCE_ID,
        locator=locator,
        observation_time_ns=time_ns,
        sequence=epoch if kind is SessionBoundaryKind.START else epoch + 1,
        kind=kind,
        producer_session_id=producer_session_id,
        continuity_epoch=epoch,
    )


def _message(
    *,
    family: VdaMessageFamily,
    time_ns: int,
    header_id: int,
    locator: str,
    value: object,
    epoch: int = 1,
    manufacturer: str = "SyntheticVendor",
    serial_number: str = "R-A",
    topic: str | None = None,
    retained: bool = False,
    duplicate: bool = False,
    digest_label: str | None = None,
    payload_override: dict[str, object] | None = None,
    source_timestamp: str = "2099-01-01T00:00:00.000Z",
    capture_codes: tuple[str, ...] = (),
) -> NormalizedVdaObservation:
    if payload_override is not None:
        payload = payload_override
    elif family is VdaMessageFamily.CONNECTION:
        payload = {"connectionState": value}
    else:
        payload = {"driving": value}
    return NormalizedVdaObservation(
        source_id=SOURCE_ID,
        locator=locator,
        observation_time_ns=time_ns,
        continuity_epoch=epoch,
        message_family=family,
        topic=topic or f"synthetic/R-A/{family.value}",
        robot_identity=RobotIdentity(manufacturer, serial_number),
        header_id=header_id,
        source_timestamp=source_timestamp,
        retained=retained,
        producer_duplicate=duplicate,
        payload_sha256=_digest(digest_label or locator),
        validated_payload=MappingProxyType(payload),
        capture_diagnostic_codes=capture_codes,
    )


def _drop(time_ns: int, locator: str, *, epoch: int = 1) -> CollectorDropObservation:
    return CollectorDropObservation(
        source_id=SOURCE_ID,
        locator=locator,
        observation_time_ns=time_ns,
        sequence=50,
        continuity_epoch=epoch,
        producer_session_id="session",
        drop_count=3,
        drop_reason="synthetic_drop",
    )


def _summary(
    *,
    complete: bool = True,
    declared_complete: bool | None = True,
    structurally_compromised: bool = False,
    verified_unchanged: bool = True,
) -> NormalizedCaptureSummary:
    return NormalizedCaptureSummary(
        source_id=SOURCE_ID,
        input_sha256=INPUT_SHA256,
        physical_record_count=20,
        accepted_record_count=20,
        declared_complete=declared_complete,
        structurally_compromised=structurally_compromised,
        verified_unchanged=verified_unchanged,
        complete=complete,
        diagnostic_codes=(),
    )


def _run_one_session(
    qualified_id: str,
    observations: tuple[NormalizedVdaObservation | CollectorDropObservation | MessageDiscontinuityObservation | CaptureDiscontinuityObservation, ...],
    *,
    end_ns: int,
    target: RobotTarget = TARGET,
    declared_complete: bool = True,
    summary_complete: bool = True,
    structurally_compromised: bool = False,
):
    executor = get_function_executor(
        qualified_id,
        source_id=SOURCE_ID,
        robot_target=target,
    )
    executor.consume(
        _capture_boundary(CaptureBoundaryKind.START, 0, "line:1")
    )
    executor.consume(
        _session_boundary(SessionBoundaryKind.START, 0, "line:2")
    )
    for observation in observations:
        executor.consume(observation)
    executor.consume(
        _session_boundary(SessionBoundaryKind.END, end_ns, "line:98")
    )
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
        )
    )


def _run_recorded_fixture(
    qualified_id: str,
    fixture_stem: str,
    *,
    target: RobotTarget = TARGET,
    source_id: str | None = None,
):
    source_id = source_id or fixture_stem.replace("_", "-")
    executor = get_function_executor(
        qualified_id,
        source_id=source_id,
        robot_target=target,
    )
    path = CAPTURE_ROOT / f"{fixture_stem}.synthetic.capture.jsonl"
    with CaptureReader(path, source_id) as reader:
        for item in reader:
            executor.consume(normalize_capture_item(item))
        summary = normalize_capture_summary(reader.summary)
    return executor.finish(summary)


class ReportedDurationTruthTests(unittest.TestCase):
    def test_connection_truth_runs_through_the_recorded_boundary(self) -> None:
        truth = json.loads(
            (TRUTH_ROOT / "connection_session_boundary.json").read_text(
                encoding="utf-8"
            )
        )
        result = _run_recorded_fixture(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            "connection_session_boundary",
        )
        actual = result.to_dict()
        expected = truth["expected"]

        self.assertIs(truth["synthetic"], True)
        self.assertEqual(actual["qualified_id"], expected["qualified_id"])
        self.assertEqual(actual["status"], expected["status"])
        self.assertEqual(actual["basis"], expected["basis"])
        self.assertEqual(actual["scope"], expected["scope"])
        self.assertEqual(
            actual["value"]["durations_ns"],
            {
                key: value * NANOSECONDS
                for key, value in expected["value_seconds"].items()
            },
        )
        self.assertEqual(
            actual["coverage"]["eligible_duration_ns"],
            expected["eligible_seconds"] * NANOSECONDS,
        )
        self.assertEqual(
            actual["coverage"]["observed_duration_ns"],
            expected["observed_seconds"] * NANOSECONDS,
        )
        self.assertEqual(
            actual["coverage"]["missing_intervals"],
            [
                {
                    "start_ns": item["start"] * NANOSECONDS,
                    "end_ns": item["end"] * NANOSECONDS,
                    "reason": item["reason"],
                }
                for item in expected["missing_intervals"]
            ],
        )
        self.assertEqual(
            actual["value"]["expected_state_silence_intervals"],
            [
                {
                    "start_ns": item["start"] * NANOSECONDS,
                    "end_ns": item["end"] * NANOSECONDS,
                    "reason": item["reason"],
                }
                for item in expected["expected_state_silence_intervals"]
            ],
        )

    def test_driving_truth_runs_through_the_recorded_boundary(self) -> None:
        truth = json.loads(
            (TRUTH_ROOT / "state_gap_missingness.json").read_text(
                encoding="utf-8"
            )
        )
        result = _run_recorded_fixture(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            "state_gap_missingness",
        )
        actual = result.to_dict()
        expected = truth["expected"]

        self.assertIs(truth["synthetic"], True)
        self.assertEqual(actual["qualified_id"], expected["qualified_id"])
        self.assertEqual(actual["status"], expected["status"])
        self.assertEqual(actual["basis"], expected["basis"])
        self.assertEqual(actual["scope"], expected["scope"])
        self.assertEqual(
            actual["value"]["durations_ns"],
            {
                key: value * NANOSECONDS
                for key, value in expected["value_seconds"].items()
            },
        )
        self.assertEqual(
            actual["coverage"]["eligible_duration_ns"],
            expected["eligible_seconds"] * NANOSECONDS,
        )
        self.assertEqual(
            actual["coverage"]["observed_duration_ns"],
            expected["observed_seconds"] * NANOSECONDS,
        )
        self.assertEqual(actual["coverage"]["ratio"], expected["coverage_ratio"])
        self.assertEqual(
            actual["value"]["excluded_intervals"],
            [
                {
                    "start_ns": item["start"] * NANOSECONDS,
                    "end_ns": item["end"] * NANOSECONDS,
                    "reason": item["reason"],
                }
                for item in expected["excluded_intervals"]
            ],
        )
        self.assertEqual(
            actual["coverage"]["missing_intervals"],
            [
                {
                    "start_ns": item["start"] * NANOSECONDS,
                    "end_ns": item["end"] * NANOSECONDS,
                    "reason": item["reason"],
                }
                for item in expected["missing_intervals"]
            ],
        )

    def test_truth_results_satisfy_the_function_result_schema(self) -> None:
        schema = json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for qualified_id, stem in (
            (
                REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
                "connection_session_boundary",
            ),
            (REPORTED_DRIVING_DURATION_QUALIFIED_ID, "state_gap_missingness"),
        ):
            with self.subTest(qualified_id=qualified_id):
                result = _run_recorded_fixture(qualified_id, stem)
                self.assertEqual(list(validator.iter_errors(result.to_dict())), [])

    def test_truth_execution_is_deterministic(self) -> None:
        for qualified_id, stem in (
            (
                REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
                "connection_session_boundary",
            ),
            (REPORTED_DRIVING_DURATION_QUALIFIED_ID, "state_gap_missingness"),
        ):
            with self.subTest(qualified_id=qualified_id):
                first = _run_recorded_fixture(qualified_id, stem)
                second = _run_recorded_fixture(qualified_id, stem)
                self.assertEqual(first.to_json(), second.to_json())


class ReportedDurationRegistryTests(unittest.TestCase):
    def test_all_reported_state_executors_are_bound(self) -> None:
        expected = {
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID,
            REPORTED_PAUSED_DURATION_QUALIFIED_ID,
            REPORTED_CHARGING_DURATION_QUALIFIED_ID,
            REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
            REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID,
            STATE_STREAM_HEALTH_QUALIFIED_ID,
        }
        self.assertLessEqual(
            expected,
            set(list_executable_function_ids()),
        )
        connection = get_function_executor(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            source_id=SOURCE_ID,
            robot_target=TARGET,
        )
        driving = get_function_executor(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            source_id=SOURCE_ID,
            robot_target=TARGET,
        )
        self.assertIsInstance(connection, ReportedConnectionStateDurationExecutor)
        self.assertIsInstance(driving, ReportedDrivingDurationExecutor)
        self.assertIsInstance(
            get_function_executor(
                REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID,
                source_id=SOURCE_ID,
                robot_target=TARGET,
            ),
            ReportedStateDurationExecutor,
        )
        self.assertIsInstance(
            get_function_executor(
                REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
                source_id=SOURCE_ID,
                robot_target=TARGET,
            ),
            ReportedBatteryStateOfChargeExecutor,
        )

    def test_robot_target_is_required_and_unknown_functions_fail_closed(self) -> None:
        for qualified_id in (
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID,
            REPORTED_PAUSED_DURATION_QUALIFIED_ID,
            REPORTED_CHARGING_DURATION_QUALIFIED_ID,
            REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
            REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID,
        ):
            with self.subTest(qualified_id=qualified_id):
                with self.assertRaisesRegex(ValueError, "requires a robot target"):
                    get_function_executor(qualified_id, source_id=SOURCE_ID)
        with self.assertRaises(KeyError):
            get_function_executor("vda.unknown@0.1.0", source_id=SOURCE_ID)

    def test_specifications_pin_truth_and_required_families(self) -> None:
        connection = get_function_spec(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID
        )
        driving = get_function_spec(REPORTED_DRIVING_DURATION_QUALIFIED_ID)
        self.assertEqual(
            connection.fixture_ids,
            ("truth.connection_session_boundary",),
        )
        self.assertEqual(driving.fixture_ids, ("truth.state_gap_missingness",))
        self.assertEqual(connection.required_message_families, ("connection",))
        self.assertEqual(
            driving.required_message_families,
            ("connection", "state"),
        )

    def test_state_feature_pack_matches_independent_truth(self) -> None:
        target = RobotTarget(
            "R-FEATURE", RobotIdentity("SyntheticVendor", "R-FEATURE")
        )
        expected = {
            REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID: {
                "AUTOMATIC": 10,
                "MANUAL": 10,
                "SERVICE": 20,
                "UNKNOWN": 0,
            },
            REPORTED_PAUSED_DURATION_QUALIFIED_ID: {
                "paused": 10,
                "not_paused": 30,
                "UNKNOWN": 0,
            },
            REPORTED_CHARGING_DURATION_QUALIFIED_ID: {
                "charging": 20,
                "not_charging": 20,
                "UNKNOWN": 0,
            },
            REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID: {
                "emergency_stop=NONE;field_violation=false": 10,
                "emergency_stop=MANUAL;field_violation=true": 10,
                "emergency_stop=REMOTE;field_violation=false": 20,
                "UNKNOWN": 0,
            },
        }
        for qualified_id, expected_seconds in expected.items():
            with self.subTest(qualified_id=qualified_id):
                result = _run_recorded_fixture(
                    qualified_id,
                    "state_feature_pack",
                    target=target,
                    source_id="state-feature-pack",
                )
                self.assertEqual(result.status, ResultStatus.COMPUTED)
                durations = result.to_dict()["value"]["durations_ns"]
                for category, seconds in expected_seconds.items():
                    self.assertEqual(durations[category], seconds * NANOSECONDS)
                self.assertEqual(result.coverage.ratio, 1.0)

        battery = _run_recorded_fixture(
            REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
            "state_feature_pack",
            target=target,
            source_id="state-feature-pack",
        )
        self.assertEqual(
            battery.to_dict()["value"],
            {
                "robot_identity": {
                    "manufacturer": "SyntheticVendor",
                    "serialNumber": "R-FEATURE",
                },
                "first_percent": 90.0,
                "minimum_percent": 60.0,
                "last_percent": 60.0,
                "sample_count": 3,
            },
        )

    def test_no_public_export_or_cli_surface_is_added(self) -> None:
        for name in (
            "RobotTarget",
            "RecordedFunctionExecutor",
            "ReportedConnectionStateDurationExecutor",
            "ReportedDrivingDurationExecutor",
        ):
            self.assertNotIn(name, mekai_open.__all__)


class ReportedDurationSemanticsTests(unittest.TestCase):
    def test_connection_state_persists_beyond_thirty_seconds(self) -> None:
        result = _run_one_session(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value="ONLINE",
                ),
            ),
            end_ns=100 * NANOSECONDS,
        )
        self.assertEqual(result.status, ResultStatus.COMPUTED)
        self.assertEqual(
            result.to_dict()["value"]["durations_ns"]["ONLINE"],
            100 * NANOSECONDS,
        )

    def test_retained_connection_establishes_but_retained_state_does_not(self) -> None:
        connection = _run_one_session(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value="ONLINE",
                    retained=True,
                ),
            ),
            end_ns=40 * NANOSECONDS,
        )
        driving = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=20 * NANOSECONDS,
                    header_id=1,
                    locator="line:4",
                    value=False,
                    retained=True,
                ),
            ),
            end_ns=40 * NANOSECONDS,
        )
        self.assertEqual(
            connection.to_dict()["value"]["durations_ns"]["ONLINE"],
            40 * NANOSECONDS,
        )
        self.assertEqual(
            driving.to_dict()["value"]["durations_ns"],
            {
                "driving": 30 * NANOSECONDS,
                "not_driving": 0,
                "UNKNOWN": 10 * NANOSECONDS,
            },
        )
        self.assertIn("RETAINED_STATE_IGNORED@line:4", driving.diagnostics)

    def test_driving_carry_forward_before_at_and_after_boundary(self) -> None:
        cases = (
            (STATE_CARRY_FORWARD_NS - 1, ResultStatus.COMPUTED, 0),
            (STATE_CARRY_FORWARD_NS, ResultStatus.COMPUTED, 0),
            (STATE_CARRY_FORWARD_NS + 1, ResultStatus.PARTIAL, 1),
        )
        for end_ns, status, unknown_ns in cases:
            with self.subTest(end_ns=end_ns):
                result = _run_one_session(
                    REPORTED_DRIVING_DURATION_QUALIFIED_ID,
                    (
                        _message(
                            family=VdaMessageFamily.STATE,
                            time_ns=0,
                            header_id=0,
                            locator="line:3",
                            value=True,
                        ),
                    ),
                    end_ns=end_ns,
                )
                self.assertEqual(result.status, status)
                self.assertEqual(
                    result.to_dict()["value"]["durations_ns"]["UNKNOWN"],
                    unknown_ns,
                )

    def test_exact_retransmission_does_not_refresh_but_dup_content_can(self) -> None:
        exact = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                    digest_label="same",
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=20 * NANOSECONDS,
                    header_id=0,
                    locator="line:4",
                    value=True,
                    digest_label="same",
                    duplicate=True,
                ),
            ),
            end_ns=40 * NANOSECONDS,
        )
        dup_new = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=20 * NANOSECONDS,
                    header_id=1,
                    locator="line:4",
                    value=False,
                    duplicate=True,
                ),
            ),
            end_ns=40 * NANOSECONDS,
        )
        self.assertEqual(
            exact.to_dict()["value"]["durations_ns"]["UNKNOWN"],
            10 * NANOSECONDS,
        )
        self.assertIn("EXACT_RETRANSMISSION@line:4", exact.diagnostics)
        self.assertIn("PRODUCER_DUPLICATE_FLAG@line:4", exact.diagnostics)
        self.assertEqual(
            dup_new.to_dict()["value"]["durations_ns"],
            {
                "driving": 20 * NANOSECONDS,
                "not_driving": 20 * NANOSECONDS,
                "UNKNOWN": 0,
            },
        )
        self.assertNotIn("EXACT_RETRANSMISSION@line:4", dup_new.diagnostics)

    def test_exact_identity_matching_ignores_other_robots(self) -> None:
        result = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=10 * NANOSECONDS,
                    header_id=0,
                    locator="line:4",
                    value=False,
                    manufacturer="OtherVendor",
                    serial_number="R-A",
                    topic="synthetic/other/state",
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=20 * NANOSECONDS,
                    header_id=0,
                    locator="line:5",
                    value=False,
                    serial_number="R-B",
                    topic="synthetic/R-B/state",
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=30 * NANOSECONDS,
                    header_id=1,
                    locator="line:6",
                    value=False,
                ),
            ),
            end_ns=40 * NANOSECONDS,
        )
        self.assertEqual(
            result.to_dict()["value"]["durations_ns"],
            {
                "driving": 30 * NANOSECONDS,
                "not_driving": 10 * NANOSECONDS,
                "UNKNOWN": 0,
            },
        )
        self.assertEqual(len(result.input_references), 2)

    def test_reused_session_labels_remain_distinct_epochs(self) -> None:
        executor = get_function_executor(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            source_id=SOURCE_ID,
            robot_target=TARGET,
        )
        observations = (
            _capture_boundary(CaptureBoundaryKind.START, 0, "line:1"),
            _session_boundary(
                SessionBoundaryKind.START,
                0,
                "line:2",
                epoch=1,
                producer_session_id="reused",
            ),
            _message(
                family=VdaMessageFamily.CONNECTION,
                time_ns=0,
                header_id=0,
                locator="line:3",
                value="ONLINE",
                epoch=1,
            ),
            _session_boundary(
                SessionBoundaryKind.END,
                20 * NANOSECONDS,
                "line:4",
                epoch=1,
                producer_session_id="reused",
            ),
            _session_boundary(
                SessionBoundaryKind.START,
                30 * NANOSECONDS,
                "line:5",
                epoch=5,
                producer_session_id="reused",
            ),
            _message(
                family=VdaMessageFamily.CONNECTION,
                time_ns=30 * NANOSECONDS,
                header_id=0,
                locator="line:6",
                value="OFFLINE",
                epoch=5,
            ),
            _session_boundary(
                SessionBoundaryKind.END,
                50 * NANOSECONDS,
                "line:7",
                epoch=5,
                producer_session_id="reused",
            ),
            _capture_boundary(
                CaptureBoundaryKind.END,
                50 * NANOSECONDS,
                "line:8",
                declared_complete=True,
            ),
        )
        for observation in observations:
            executor.consume(observation)
        result = executor.finish(_summary())
        self.assertEqual(
            result.to_dict()["value"]["durations_ns"],
            {
                "ONLINE": 20 * NANOSECONDS,
                "OFFLINE": 20 * NANOSECONDS,
                "HIBERNATING": 0,
                "CONNECTION_BROKEN": 0,
                "UNKNOWN": 10 * NANOSECONDS,
            },
        )

    def test_drop_breaks_continuity_without_inventing_drop_duration(self) -> None:
        result = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                ),
                _drop(10 * NANOSECONDS, "line:4"),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=20 * NANOSECONDS,
                    header_id=1,
                    locator="line:5",
                    value=False,
                ),
            ),
            end_ns=30 * NANOSECONDS,
        )
        self.assertEqual(
            result.to_dict()["value"]["durations_ns"],
            {
                "driving": 10 * NANOSECONDS,
                "not_driving": 10 * NANOSECONDS,
                "UNKNOWN": 10 * NANOSECONDS,
            },
        )
        self.assertIn("COLLECTOR_DROP@line:4", result.diagnostics)
        self.assertNotIn("drop_duration_ns", json.dumps(result.to_dict()))

    def test_header_gap_conflict_regression_and_overflow_are_distinct(self) -> None:
        cases = (
            (7, "gap", "HEADER_GAP", 10 * NANOSECONDS),
            (5, "conflict", "HEADER_CONFLICT", 0),
            (4, "regression", "HEADER_REGRESSION", 0),
            (MAX_VDA_HEADER_ID + 1, "overflow", "HEADER_OUT_OF_RANGE", 0),
        )
        for header_id, label, code, expected_not_driving in cases:
            with self.subTest(label=label):
                result = _run_one_session(
                    REPORTED_DRIVING_DURATION_QUALIFIED_ID,
                    (
                        _message(
                            family=VdaMessageFamily.STATE,
                            time_ns=0,
                            header_id=5,
                            locator="line:3",
                            value=True,
                            digest_label="first",
                        ),
                        _message(
                            family=VdaMessageFamily.STATE,
                            time_ns=10 * NANOSECONDS,
                            header_id=header_id,
                            locator="line:4",
                            value=False,
                            digest_label=label,
                        ),
                    ),
                    end_ns=20 * NANOSECONDS,
                )
                value = result.to_dict()["value"]["durations_ns"]
                self.assertEqual(value["driving"], 10 * NANOSECONDS)
                self.assertEqual(value["not_driving"], expected_not_driving)
                self.assertIn(f"{code}@line:4", result.diagnostics)
                self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_uint32_extremes_can_establish_the_first_header(self) -> None:
        for header_id in (0, MAX_VDA_HEADER_ID):
            with self.subTest(header_id=header_id):
                result = _run_one_session(
                    REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
                    (
                        _message(
                            family=VdaMessageFamily.CONNECTION,
                            time_ns=0,
                            header_id=header_id,
                            locator="line:3",
                            value="ONLINE",
                        ),
                    ),
                    end_ns=10,
                )
                self.assertEqual(result.status, ResultStatus.COMPUTED)
                self.assertEqual(
                    result.to_dict()["value"]["durations_ns"]["ONLINE"],
                    10,
                )

    def test_invalid_connection_headers_create_no_reported_transition(self) -> None:
        cannot_create = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                ),
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=10 * NANOSECONDS,
                    header_id=MAX_VDA_HEADER_ID + 1,
                    locator="line:4",
                    value="HIBERNATING",
                ),
            ),
            end_ns=40 * NANOSECONDS,
        )
        cannot_end = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value="HIBERNATING",
                ),
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=10 * NANOSECONDS,
                    header_id=MAX_VDA_HEADER_ID + 1,
                    locator="line:4",
                    value="ONLINE",
                ),
            ),
            end_ns=40 * NANOSECONDS,
        )
        self.assertEqual(
            cannot_create.to_dict()["value"]["excluded_interval_count"], 0
        )
        self.assertEqual(
            cannot_create.to_dict()["value"]["durations_ns"]["UNKNOWN"],
            30 * NANOSECONDS,
        )
        self.assertEqual(
            cannot_end.to_dict()["value"]["excluded_intervals"],
            [
                {
                    "start_ns": 0,
                    "end_ns": 10 * NANOSECONDS,
                    "reason": "CONFIRMED_HIBERNATION",
                }
            ],
        )
        self.assertEqual(
            cannot_end.to_dict()["value"]["durations_ns"]["UNKNOWN"],
            30 * NANOSECONDS,
        )
        self.assertIn("HEADER_OUT_OF_RANGE@line:4", cannot_create.diagnostics)
        self.assertIn("HEADER_OUT_OF_RANGE@line:4", cannot_end.diagnostics)

    def test_invalid_messages_and_missing_fields_never_create_transitions(self) -> None:
        invalid = MessageDiscontinuityObservation(
            source_id=SOURCE_ID,
            locator="line:4",
            observation_time_ns=10 * NANOSECONDS,
            continuity_epoch=1,
            message_family=VdaMessageFamily.STATE,
            topic="synthetic/R-A/state",
            payload_sha256=_digest("invalid"),
            capture_accepted=True,
            vda_valid=False,
            capture_diagnostic_codes=(),
            vda_diagnostic_codes=("SCHEMA_VIOLATION",),
        )
        result = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                ),
                invalid,
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=20 * NANOSECONDS,
                    header_id=1,
                    locator="line:5",
                    value=False,
                ),
            ),
            end_ns=30 * NANOSECONDS,
        )
        missing_field = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                    payload_override={},
                ),
            ),
            end_ns=10,
        )
        self.assertEqual(
            result.to_dict()["value"]["durations_ns"]["UNKNOWN"],
            10 * NANOSECONDS,
        )
        self.assertIn("VDA_MESSAGE_INVALID@line:4", result.diagnostics)
        self.assertIn(
            "REQUIRED_FIELD_MISSING@line:3",
            missing_field.diagnostics,
        )

        rejected = MessageDiscontinuityObservation(
            source_id=SOURCE_ID,
            locator="line:4",
            observation_time_ns=10,
            continuity_epoch=None,
            message_family=VdaMessageFamily.STATE,
            topic="synthetic/R-A/state",
            payload_sha256=_digest("rejected"),
            capture_accepted=False,
            vda_valid=True,
            capture_diagnostic_codes=("SEQUENCE_MISMATCH",),
            vda_diagnostic_codes=(),
        )
        rejected_result = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (rejected,),
            end_ns=20,
        )
        self.assertIn(
            "CAPTURE_MESSAGE_REJECTED@line:4",
            rejected_result.diagnostics,
        )

        discontinuity = CaptureDiscontinuityObservation(
            source_id=SOURCE_ID,
            locator="line:4",
            observation_time_ns=None,
            record_kind=None,
            diagnostic_codes=("MALFORMED_JSON",),
        )
        discontinuity_result = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (discontinuity,),
            end_ns=20,
        )
        self.assertIn(
            "CAPTURE_RECORD_INVALID@line:4",
            discontinuity_result.diagnostics,
        )

    def test_no_target_observation_is_partial_unknown_not_invented_state(self) -> None:
        result = _run_one_session(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value="ONLINE",
                    manufacturer="OtherVendor",
                ),
            ),
            end_ns=10,
        )
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertEqual(
            result.to_dict()["value"]["durations_ns"]["UNKNOWN"],
            10,
        )
        self.assertEqual(result.input_references, ())
        self.assertIn("NO_TARGET_OBSERVATION", result.diagnostics)

    def test_source_timestamp_is_ignored_and_receive_regression_is_not_sorted(self) -> None:
        source_timestamp_only = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value=True,
                    source_timestamp="2099-01-02T00:00:00.000Z",
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=10,
                    header_id=1,
                    locator="line:4",
                    value=False,
                    source_timestamp="1999-01-01T00:00:00.000Z",
                ),
            ),
            end_ns=20,
        )
        regressed = _run_one_session(
            REPORTED_DRIVING_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=10,
                    header_id=0,
                    locator="line:3",
                    value=True,
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=5,
                    header_id=1,
                    locator="line:4",
                    value=False,
                    capture_codes=("UTC_TIME_REGRESSION",),
                ),
                _message(
                    family=VdaMessageFamily.STATE,
                    time_ns=20,
                    header_id=2,
                    locator="line:5",
                    value=False,
                ),
            ),
            end_ns=30,
        )
        self.assertEqual(
            source_timestamp_only.to_dict()["value"]["durations_ns"],
            {"driving": 10, "not_driving": 10, "UNKNOWN": 0},
        )
        self.assertEqual(
            regressed.to_dict()["value"]["durations_ns"],
            {"driving": 0, "not_driving": 10, "UNKNOWN": 20},
        )
        self.assertIn("UTC_TIME_REGRESSION@line:4", regressed.diagnostics)

    def test_missing_interval_detail_truncation_keeps_exact_coverage(self) -> None:
        observations = (
            _message(
                family=VdaMessageFamily.STATE,
                time_ns=0,
                header_id=0,
                locator="line:3",
                value=True,
            ),
            _drop(10, "line:4"),
            _message(
                family=VdaMessageFamily.STATE,
                time_ns=20,
                header_id=1,
                locator="line:5",
                value=False,
            ),
            _drop(30, "line:6"),
            _message(
                family=VdaMessageFamily.STATE,
                time_ns=40,
                header_id=2,
                locator="line:7",
                value=True,
            ),
        )
        with mock.patch(
            "mekai_open.reported_durations.MAX_REPORTED_DURATION_INTERVAL_DETAILS",
            1,
        ):
            result = _run_one_session(
                REPORTED_DRIVING_DURATION_QUALIFIED_ID,
                observations,
                end_ns=50,
            )
        self.assertEqual(result.coverage.eligible_duration_ns, 50)
        self.assertEqual(result.coverage.observed_duration_ns, 30)
        self.assertEqual(result.coverage.known_missing_interval_count, 2)
        self.assertEqual(len(result.coverage.missing_intervals), 1)
        self.assertIs(result.coverage.missing_interval_details_truncated, True)
        self.assertIn("INTERVAL_DETAILS_TRUNCATED", result.diagnostics)
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_input_mutation_and_undefined_windows_fail_closed(self) -> None:
        executor = get_function_executor(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            source_id=SOURCE_ID,
            robot_target=TARGET,
        )
        executor.consume(
            _capture_boundary(CaptureBoundaryKind.START, 0, "line:1")
        )
        executor.consume(
            _session_boundary(SessionBoundaryKind.START, 0, "line:2")
        )
        executor.consume(
            _message(
                family=VdaMessageFamily.CONNECTION,
                time_ns=0,
                header_id=0,
                locator="line:3",
                value="ONLINE",
            )
        )
        executor.consume(InputMutationObservation(SOURCE_ID))
        changed = executor.finish(None)
        self.assertEqual(changed.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIsNone(changed.value)
        self.assertIsNone(changed.window)
        self.assertEqual(changed.coverage.eligible_duration_ns, 0)
        self.assertEqual(changed.input_references, ())
        self.assertIn("INPUT_CHANGED", changed.diagnostics)

        undefined = get_function_executor(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            source_id=SOURCE_ID,
            robot_target=TARGET,
        )
        undefined.consume(
            _capture_boundary(CaptureBoundaryKind.START, 0, "line:1")
        )
        missing_end = undefined.finish(
            _summary(complete=False, declared_complete=None)
        )
        self.assertEqual(missing_end.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIn("WINDOW_UNDEFINED", missing_end.diagnostics)

    def test_declared_incomplete_capture_keeps_meaningful_partial_value(self) -> None:
        result = _run_one_session(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            (
                _message(
                    family=VdaMessageFamily.CONNECTION,
                    time_ns=0,
                    header_id=0,
                    locator="line:3",
                    value="ONLINE",
                ),
            ),
            end_ns=10,
            declared_complete=False,
            summary_complete=False,
        )
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertEqual(
            result.to_dict()["value"]["durations_ns"]["ONLINE"],
            10,
        )
        self.assertIn("CAPTURE_INCOMPLETE", result.diagnostics)

    def test_diagnostics_references_targets_and_values_are_bounded_or_immutable(self) -> None:
        with mock.patch(
            "mekai_open.reported_durations.MAX_REPORTED_DURATION_DIAGNOSTICS",
            1,
        ), mock.patch(
            "mekai_open.reported_durations.MAX_REPORTED_DURATION_INPUT_REFERENCES",
            1,
        ):
            result = _run_one_session(
                REPORTED_DRIVING_DURATION_QUALIFIED_ID,
                (
                    _message(
                        family=VdaMessageFamily.STATE,
                        time_ns=0,
                        header_id=0,
                        locator="line:3",
                        value=True,
                        retained=True,
                    ),
                    _message(
                        family=VdaMessageFamily.STATE,
                        time_ns=1,
                        header_id=MAX_VDA_HEADER_ID + 1,
                        locator="line:4",
                        value=False,
                    ),
                ),
                end_ns=10,
            )
        self.assertLessEqual(len(result.input_references), 1)
        self.assertIn("DIAGNOSTICS_TRUNCATED", result.diagnostics)
        self.assertLessEqual(
            len(result.diagnostics),
            MAX_REPORTED_DURATION_DIAGNOSTICS + 3,
        )
        with self.assertRaises(TypeError):
            result.value["new"] = 1
        with self.assertRaises(FrozenInstanceError):
            TARGET.subject_id = "changed"

        with self.assertRaises(ValueError):
            RobotTarget(
                "R" * (MAX_ROBOT_TARGET_SUBJECT_ID_CHARACTERS + 1),
                TARGET.robot_identity,
            )
        with self.assertRaises(ValueError):
            RobotTarget(
                "R1",
                RobotIdentity(
                    "M" * (MAX_ROBOT_TARGET_IDENTITY_CHARACTERS + 1),
                    "R-A",
                ),
            )

    def test_core_has_no_capture_mqtt_ros_or_dynamic_execution_dependency(self) -> None:
        path = ROOT / "src" / "mekai_open" / "reported_durations.py"
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
        forbidden_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"eval", "exec", "__import__"}:
                    forbidden_calls.append(node.func.id)
        self.assertEqual(forbidden_calls, [])

    def test_named_limits_are_positive_and_no_target_mismatch_state_is_retained(self) -> None:
        self.assertEqual(STATE_CARRY_FORWARD_NS, 30 * NANOSECONDS)
        for limit in (
            MAX_REPORTED_DURATION_DIAGNOSTICS,
            MAX_REPORTED_DURATION_INPUT_REFERENCES,
            MAX_REPORTED_DURATION_INTERVAL_DETAILS,
        ):
            self.assertGreater(limit, 0)
        mismatches = tuple(
            _message(
                family=VdaMessageFamily.CONNECTION,
                time_ns=index,
                header_id=index,
                locator=f"line:{index + 3}",
                value="ONLINE",
                serial_number=f"other-{index}",
                topic=f"synthetic/other-{index}/connection",
            )
            for index in range(100)
        )
        result = _run_one_session(
            REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
            mismatches,
            end_ns=101,
        )
        self.assertEqual(result.input_references, ())
        self.assertNotIn("RESOURCE_LIMIT", " ".join(result.diagnostics))

    def test_real_reader_preserves_vda_invalid_message_as_missingness(self) -> None:
        original = (
            CAPTURE_ROOT / "state_gap_missingness.synthetic.capture.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        invalid_payload = base64.b64encode(
            b'{"version":"3.0.0"}'
        ).decode("ascii")
        record = json.loads(original[2])
        record["payload_base64"] = invalid_payload
        original[2] = json.dumps(record, separators=(",", ":"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.synthetic.capture.jsonl"
            path.write_text("\n".join(original) + "\n", encoding="utf-8")
            executor = get_function_executor(
                REPORTED_DRIVING_DURATION_QUALIFIED_ID,
                source_id=SOURCE_ID,
                robot_target=TARGET,
            )
            with CaptureReader(path, SOURCE_ID) as reader:
                for item in reader:
                    executor.consume(normalize_capture_item(item))
                summary = normalize_capture_summary(reader.summary)
            result = executor.finish(summary)
        self.assertEqual(result.status, ResultStatus.PARTIAL)
        self.assertTrue(
            any(item.startswith("VDA_MESSAGE_INVALID@") for item in result.diagnostics)
        )


if __name__ == "__main__":
    unittest.main()
    REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
    REPORTED_CHARGING_DURATION_QUALIFIED_ID,
