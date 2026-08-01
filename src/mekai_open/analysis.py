"""Single-pass recorded-capture orchestration and deterministic run results."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from .capture_adapter import normalize_capture_item, normalize_capture_summary
from .capture_jsonl import CaptureReader
from .contracts import FunctionResult
from .event_functions import (
    ACTIVE_ERROR_EPISODES_QUALIFIED_ID,
    FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID,
    OBSERVED_ORDERS_QUALIFIED_ID,
    PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID,
    PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID,
)
from .function_registry import (
    get_function_executor,
    list_executable_function_ids,
)
from .input_fingerprint import (
    InputChangedError,
    fingerprint_regular_file,
    open_verified_regular_file,
    verify_unchanged,
)
from .json_safety import StrictJsonDecodingError, decode_strict_json
from .observations import InputMutationObservation, RobotIdentity, RobotTarget
from .reported_durations import (
    REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
    REPORTED_CHARGING_DURATION_QUALIFIED_ID,
    REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
    REPORTED_DRIVING_DURATION_QUALIFIED_ID,
    REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID,
    REPORTED_PAUSED_DURATION_QUALIFIED_ID,
    REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID,
)
from .source_ids import validate_source_id
from .state_stream_health import STATE_STREAM_HEALTH_QUALIFIED_ID
from .vda_schemas import DEFAULT_MAX_MESSAGE_BYTES, validate_message_byte_limit

ANALYSIS_CONFIG_SCHEMA_ID = "mekai.analysis_config/0.1"
ANALYSIS_RUN_SCHEMA_ID = "mekai.analysis_run/0.1"
MAX_CONFIG_BYTES = 1 << 20
MAX_CONFIGURED_ROBOTS = 1_024
MAX_RUN_EXCEPTIONS = 10_000

_ROBOT_FUNCTION_IDS = (
    REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
    REPORTED_DRIVING_DURATION_QUALIFIED_ID,
    REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID,
    REPORTED_PAUSED_DURATION_QUALIFIED_ID,
    REPORTED_CHARGING_DURATION_QUALIFIED_ID,
    REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
    REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID,
)
_COHORT_FUNCTION_IDS = (
    OBSERVED_ORDERS_QUALIFIED_ID,
    ACTIVE_ERROR_EPISODES_QUALIFIED_ID,
    PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID,
    PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID,
    FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID,
)


@dataclass(frozen=True, slots=True)
class AnalysisConfiguration:
    """Bind one source to explicit robot subjects and parser limits."""

    source_id: str
    robots: tuple[RobotTarget, ...]
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        robots = tuple(self.robots)
        if not robots or len(robots) > MAX_CONFIGURED_ROBOTS:
            raise ValueError("configuration requires 1..1024 robot targets")
        if len({item.subject_id for item in robots}) != len(robots):
            raise ValueError("configured robot subject IDs must be unique")
        identities = [item.robot_identity for item in robots]
        if len(set(identities)) != len(identities):
            raise ValueError("configured robot identities must be unique")
        validate_message_byte_limit(self.max_message_bytes)
        object.__setattr__(
            self,
            "robots",
            tuple(sorted(robots, key=lambda item: item.subject_id)),
        )

    def to_dict(self) -> dict[str, object]:
        """Return a portable configuration representation without local paths."""

        return {
            "schema": ANALYSIS_CONFIG_SCHEMA_ID,
            "source_id": self.source_id,
            "robots": [
                {
                    "subject_id": target.subject_id,
                    "manufacturer": target.robot_identity.manufacturer,
                    "serial_number": target.robot_identity.serial_number,
                }
                for target in self.robots
            ],
            "limits": {"message_bytes": self.max_message_bytes},
        }


@dataclass(frozen=True, slots=True)
class AnalysisRun:
    """Contain one authoritative deterministic run document in memory."""

    analysis_id: str
    source_id: str
    input_sha256: str
    input_size_bytes: int
    configured_robots: tuple[RobotTarget, ...]
    results: tuple[FunctionResult, ...]
    exceptions: tuple[dict[str, object], ...]
    exceptions_truncated: bool

    def to_dict(self) -> dict[str, object]:
        """Return the canonical machine-readable run document."""

        status_counts = {"COMPUTED": 0, "PARTIAL": 0, "NOT_COMPUTABLE": 0}
        for result in self.results:
            status_counts[result.status.value] += 1
        return {
            "schema": ANALYSIS_RUN_SCHEMA_ID,
            "analysis_id": self.analysis_id,
            "protocol": {"name": "VDA 5050", "version": "3.0.0"},
            "qualification": "synthetic/lab-qualified",
            "source": {
                "source_id": self.source_id,
                "input_sha256": self.input_sha256,
                "input_size_bytes": self.input_size_bytes,
            },
            "configured_robots": [
                {
                    "subject_id": target.subject_id,
                    "robot_identity": target.robot_identity.to_dict(),
                }
                for target in self.configured_robots
            ],
            "summary": {
                "function_result_count": len(self.results),
                "status_counts": status_counts,
                "exception_count": len(self.exceptions),
                "exceptions_truncated": self.exceptions_truncated,
            },
            "results": [result.to_dict() for result in self.results],
            "exceptions": list(self.exceptions),
        }

    def to_json(self) -> str:
        """Serialize the run as canonical compact strict JSON."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def load_analysis_configuration(
    path: str | os.PathLike[str],
) -> AnalysisConfiguration:
    """Read a bounded strict JSON configuration from a regular non-symlink file."""

    fingerprint = fingerprint_regular_file(path)
    if fingerprint.entries[0].size_bytes > MAX_CONFIG_BYTES:
        raise ValueError("analysis configuration exceeds 1 MiB")
    with open_verified_regular_file(fingerprint) as stream:
        payload = stream.read(MAX_CONFIG_BYTES + 1)
    verify_unchanged(fingerprint)
    try:
        decoded = decode_strict_json(payload)
    except StrictJsonDecodingError as exc:
        raise ValueError("analysis configuration is not strict JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("analysis configuration must be a JSON object")
    return _parse_configuration(decoded)


def analyze_capture(
    path: str | os.PathLike[str],
    configuration: AnalysisConfiguration,
) -> AnalysisRun:
    """Execute all 13 built-ins over one capture in a single normalized pass."""

    if not isinstance(configuration, AnalysisConfiguration):
        raise TypeError("configuration must be an AnalysisConfiguration")
    source_id = configuration.source_id
    preflight = fingerprint_regular_file(path)
    input_size_bytes = preflight.entries[0].size_bytes
    executors: list[tuple[str, str | None, object]] = []
    executors.append(
        (
            STATE_STREAM_HEALTH_QUALIFIED_ID,
            None,
            get_function_executor(
                STATE_STREAM_HEALTH_QUALIFIED_ID, source_id=source_id
            ),
        )
    )
    for qualified_id in _COHORT_FUNCTION_IDS:
        executors.append(
            (
                qualified_id,
                None,
                get_function_executor(qualified_id, source_id=source_id),
            )
        )
    for target in configuration.robots:
        for qualified_id in _ROBOT_FUNCTION_IDS:
            executors.append(
                (
                    qualified_id,
                    target.subject_id,
                    get_function_executor(
                        qualified_id,
                        source_id=source_id,
                        robot_target=target,
                    ),
                )
            )

    try:
        with CaptureReader(
            path,
            source_id,
            max_message_bytes=configuration.max_message_bytes,
        ) as reader:
            for item in reader:
                observation = normalize_capture_item(item)
                for _, _, executor in executors:
                    executor.consume(observation)
            summary = normalize_capture_summary(reader.summary)
            if summary.input_sha256 != preflight.sha256:
                raise InputChangedError(
                    "INPUT_CHANGED: capture changed between qualification boundaries"
                )
    except InputChangedError:
        mutation = InputMutationObservation(source_id)
        for _, _, executor in executors:
            executor.consume(mutation)
        results = tuple(executor.finish(None) for _, _, executor in executors)
        return _build_run(
            configuration,
            "0" * 64,
            0,
            results,
        )

    results = tuple(executor.finish(summary) for _, _, executor in executors)
    expected_count = 1 + len(_COHORT_FUNCTION_IDS) + (
        len(_ROBOT_FUNCTION_IDS) * len(configuration.robots)
    )
    if len(results) != expected_count:
        raise RuntimeError("analysis result count is internally inconsistent")
    if set(list_executable_function_ids()) != {
        STATE_STREAM_HEALTH_QUALIFIED_ID,
        *_COHORT_FUNCTION_IDS,
        *_ROBOT_FUNCTION_IDS,
    }:
        raise RuntimeError("analysis orchestration does not cover the registry")
    return _build_run(
        configuration,
        summary.input_sha256,
        input_size_bytes,
        results,
    )


def _parse_configuration(value: dict[str, object]) -> AnalysisConfiguration:
    """Validate the exact analysis configuration envelope."""

    if set(value) != {"schema", "source_id", "robots", "limits"}:
        raise ValueError("analysis configuration fields are not exact")
    if value.get("schema") != ANALYSIS_CONFIG_SCHEMA_ID:
        raise ValueError("unsupported analysis configuration schema")
    source_id = value.get("source_id")
    robots = value.get("robots")
    limits = value.get("limits")
    if not isinstance(source_id, str):
        raise ValueError("source_id must be a string")
    if not isinstance(robots, list):
        raise ValueError("robots must be an array")
    if not isinstance(limits, dict) or set(limits) != {"message_bytes"}:
        raise ValueError("limits must contain only message_bytes")
    message_bytes = limits.get("message_bytes")
    if isinstance(message_bytes, bool) or not isinstance(message_bytes, int):
        raise ValueError("message_bytes must be an integer")
    targets: list[RobotTarget] = []
    for row in robots:
        if not isinstance(row, dict) or set(row) != {
            "subject_id",
            "manufacturer",
            "serial_number",
        }:
            raise ValueError("each robot target must use the exact declared fields")
        subject = row.get("subject_id")
        manufacturer = row.get("manufacturer")
        serial = row.get("serial_number")
        if not all(isinstance(item, str) for item in (subject, manufacturer, serial)):
            raise ValueError("robot target values must be strings")
        targets.append(
            RobotTarget(
                str(subject),
                RobotIdentity(str(manufacturer), str(serial)),
            )
        )
    return AnalysisConfiguration(source_id, tuple(targets), message_bytes)


def _build_run(
    configuration: AnalysisConfiguration,
    input_sha256: str,
    input_size_bytes: int,
    results: tuple[FunctionResult, ...],
) -> AnalysisRun:
    """Build stable run identity and bounded exception projections."""

    exceptions, truncated = _project_exceptions(results)
    identity = hashlib.sha256()
    identity.update(b"mekai-analysis-run-v1\0")
    identity.update(configuration.source_id.encode("utf-8"))
    identity.update(bytes.fromhex(input_sha256))
    identity.update(
        json.dumps(
            configuration.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    for result in results:
        identity.update(result.to_json().encode("utf-8"))
    return AnalysisRun(
        analysis_id=identity.hexdigest(),
        source_id=configuration.source_id,
        input_sha256=input_sha256,
        input_size_bytes=input_size_bytes,
        configured_robots=configuration.robots,
        results=results,
        exceptions=exceptions,
        exceptions_truncated=truncated,
    )


def _project_exceptions(
    results: tuple[FunctionResult, ...],
) -> tuple[tuple[dict[str, object], ...], bool]:
    """Project result status, diagnostics, errors, and non-finished orders."""

    rows: list[dict[str, object]] = []
    truncated = False

    def append(row: dict[str, object]) -> None:
        nonlocal truncated
        if len(rows) >= MAX_RUN_EXCEPTIONS:
            truncated = True
            return
        rows.append(row)

    for result in results:
        scope = result.scope.to_dict()
        if result.status.value != "COMPUTED":
            append(
                {
                    "kind": "RESULT_STATUS",
                    "qualified_id": result.qualified_id,
                    "scope": scope,
                    "status": result.status.value,
                }
            )
        for diagnostic in result.diagnostics:
            append(
                {
                    "kind": "DIAGNOSTIC",
                    "qualified_id": result.qualified_id,
                    "scope": scope,
                    "code": diagnostic,
                }
            )
        value = result.to_dict()["value"]
        if result.qualified_id == ACTIVE_ERROR_EPISODES_QUALIFIED_ID and isinstance(
            value, dict
        ):
            for episode in value.get("episodes", []):
                append(
                    {
                        "kind": "ERROR_EPISODE",
                        "qualified_id": result.qualified_id,
                        "episode": episode,
                    }
                )
        if result.qualified_id == PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID and isinstance(
            value, dict
        ):
            for outcome in value.get("outcomes", []):
                if outcome.get("outcome") != "INFERRED_FINISHED":
                    append(
                        {
                            "kind": "ORDER_OUTCOME",
                            "qualified_id": result.qualified_id,
                            "outcome": outcome,
                        }
                    )
    return tuple(rows), truncated
