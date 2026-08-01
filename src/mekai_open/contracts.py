"""Immutable function and result contracts."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping

from .json_safety import contains_invalid_unicode_scalar
from .source_ids import validate_source_id

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]*$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESULT_SCHEMA = "mekai.function_result/0.1"
_MESSAGE_FAMILIES = frozenset(
    {"connection", "order", "instantActions", "state"}
)


class ResultStatus(StrEnum):
    """Whether a function produced a complete, partial, or absent value."""

    COMPUTED = "COMPUTED"
    PARTIAL = "PARTIAL"
    NOT_COMPUTABLE = "NOT_COMPUTABLE"


class ResultBasis(StrEnum):
    """Whether a result repeats reported data or derives an inference."""

    REPORTED = "REPORTED"
    INFERRED = "INFERRED"


class ScopeKind(StrEnum):
    """Supported subject categories for a function result."""

    ROBOT = "ROBOT"
    OBSERVED_ROBOT_COHORT = "OBSERVED_ROBOT_COHORT"
    SOURCE = "SOURCE"


@dataclass(frozen=True, slots=True)
class ResultScope:
    """Canonical kind and stable subject identities covered by a result."""

    kind: ScopeKind
    subject_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        subject_ids = tuple(self.subject_ids)
        if not subject_ids or any(not item for item in subject_ids):
            raise ValueError("result scope requires non-empty subject IDs")
        if len(set(subject_ids)) != len(subject_ids):
            raise ValueError("result scope subject IDs must be unique")
        object.__setattr__(self, "subject_ids", tuple(sorted(subject_ids)))
        _validate_json_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible scope representation."""

        return {"kind": self.kind.value, "subject_ids": list(self.subject_ids)}


@dataclass(frozen=True, slots=True)
class EvaluationWindow:
    """Half-open observation window expressed in nanoseconds."""

    start_ns: int
    end_ns: int

    def __post_init__(self) -> None:
        if self.start_ns < 0 or self.end_ns <= self.start_ns:
            raise ValueError("evaluation window must be positive and non-empty")

    @property
    def duration_ns(self) -> int:
        """Return the window duration in nanoseconds."""

        return self.end_ns - self.start_ns

    def to_dict(self) -> dict[str, int]:
        """Return the JSON-compatible evaluation window."""

        return {"start_ns": self.start_ns, "end_ns": self.end_ns}


@dataclass(frozen=True, slots=True)
class MissingInterval:
    """A non-empty interval where eligible evidence was unavailable."""

    start_ns: int
    end_ns: int
    reason: str

    def __post_init__(self) -> None:
        if self.start_ns < 0 or self.end_ns <= self.start_ns:
            raise ValueError("missing interval must be positive and non-empty")
        if not self.reason:
            raise ValueError("missing interval requires a reason")
        _validate_json_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible missing interval."""

        return {
            "start_ns": self.start_ns,
            "end_ns": self.end_ns,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class Coverage:
    """Exact observed duration, or bounded missing detail when it is unavailable."""

    eligible_duration_ns: int
    observed_duration_ns: int | None
    missing_intervals: tuple[MissingInterval, ...] = ()
    known_missing_interval_count: int | None = None
    missing_interval_details_truncated: bool = False

    def __post_init__(self) -> None:
        if self.eligible_duration_ns < 0:
            raise ValueError("eligible duration cannot be negative")
        if not isinstance(self.missing_interval_details_truncated, bool):
            raise ValueError("missing interval truncation flag must be boolean")
        if self.observed_duration_ns is None:
            if not self.missing_interval_details_truncated:
                raise ValueError(
                    "unavailable observed duration requires truncated interval detail"
                )
        elif not 0 <= self.observed_duration_ns <= self.eligible_duration_ns:
            raise ValueError("observed duration must be within eligible duration")
        intervals = tuple(
            sorted(
                self.missing_intervals,
                key=lambda item: (item.start_ns, item.end_ns, item.reason),
            )
        )
        count = self.known_missing_interval_count
        if count is None:
            count = len(intervals)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("known missing interval count must be non-negative")
        if count < len(intervals):
            raise ValueError(
                "known missing interval count cannot be smaller than retained detail"
            )
        if self.missing_interval_details_truncated and count <= len(intervals):
            raise ValueError(
                "truncated missing interval detail requires an omitted interval"
            )
        object.__setattr__(
            self,
            "missing_intervals",
            intervals,
        )
        object.__setattr__(self, "known_missing_interval_count", count)

    @property
    def ratio(self) -> float | None:
        """Return the exact coverage ratio when both durations are available."""

        if self.eligible_duration_ns == 0 or self.observed_duration_ns is None:
            return None
        return self.observed_duration_ns / self.eligible_duration_ns

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible coverage representation."""

        return {
            "eligible_duration_ns": self.eligible_duration_ns,
            "observed_duration_ns": self.observed_duration_ns,
            "ratio": self.ratio,
            "missing_intervals": [
                interval.to_dict() for interval in self.missing_intervals
            ],
            "known_missing_interval_count": self.known_missing_interval_count,
            "missing_interval_details_truncated": (
                self.missing_interval_details_truncated
            ),
        }


@dataclass(frozen=True, slots=True)
class InputReference:
    """Trace a result to an exact record under one portable source ID."""

    source_id: str
    input_sha256: str
    locator: str
    message_family: str
    topic: str | None = None
    header_identity: str | None = None

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        if not self.locator or not self.message_family:
            raise ValueError("input reference identity fields cannot be empty")
        if self.message_family not in _MESSAGE_FAMILIES:
            raise ValueError(f"unsupported message family: {self.message_family}")
        if not _SHA256.fullmatch(self.input_sha256):
            raise ValueError(
                "input_sha256 must be 64 lowercase hexadecimal characters"
            )
        if self.topic is not None and not self.topic:
            raise ValueError("topic cannot be empty when provided")
        if self.header_identity is not None and not self.header_identity:
            raise ValueError("header_identity cannot be empty when provided")
        _validate_json_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible evidence reference."""

        result: dict[str, Any] = {
            "source_id": self.source_id,
            "input_sha256": self.input_sha256,
            "locator": self.locator,
            "message_family": self.message_family,
        }
        if self.topic is not None:
            result["topic"] = self.topic
        if self.header_identity is not None:
            result["header_identity"] = self.header_identity
        return result


@dataclass(frozen=True, slots=True)
class FieldRequirement:
    """Fields a function requires from one VDA message family."""

    message_family: str
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        fields = tuple(sorted(self.fields))
        if (
            self.message_family not in _MESSAGE_FAMILIES
            or not fields
            or any(not item for item in fields)
        ):
            raise ValueError(
                "field requirement needs a supported family and non-empty fields"
            )
        if len(set(fields)) != len(fields):
            raise ValueError("field requirement fields must be unique")
        object.__setattr__(self, "fields", fields)
        _validate_json_value(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible field requirement."""

        return {
            "message_family": self.message_family,
            "fields": list(self.fields),
        }


@dataclass(frozen=True, slots=True)
class FunctionSpec:
    """Versioned semantic contract for one built-in product function."""

    function_id: str
    version: str
    required_message_families: tuple[str, ...]
    required_fields: tuple[FieldRequirement, ...]
    method: str
    basis: ResultBasis
    missing_data_requirements: tuple[str, ...]
    result_schema: str
    fixture_ids: tuple[str, ...]
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.function_id):
            raise ValueError(f"invalid function_id: {self.function_id!r}")
        if not _SEMVER.fullmatch(self.version):
            raise ValueError(f"invalid semantic version: {self.version!r}")
        families = tuple(sorted(self.required_message_families))
        fields = tuple(
            sorted(self.required_fields, key=lambda item: item.message_family)
        )
        missing = tuple(sorted(self.missing_data_requirements))
        fixtures = tuple(sorted(self.fixture_ids))
        if not families:
            raise ValueError("function requires at least one message family")
        if (
            any(family not in _MESSAGE_FAMILIES for family in families)
            or len(set(families)) != len(families)
        ):
            raise ValueError("function message families must be supported and unique")
        if any(item.message_family not in families for item in fields):
            raise ValueError(
                "required field families must also be required message families"
            )
        if len({item.message_family for item in fields}) != len(fields):
            raise ValueError("required fields may declare each family only once")
        if not self.method:
            raise ValueError("method is required")
        if self.result_schema != _RESULT_SCHEMA:
            raise ValueError(f"result_schema must be {_RESULT_SCHEMA}")
        if any(not item for item in missing) or len(set(missing)) != len(missing):
            raise ValueError(
                "missing-data requirements must be non-empty and unique"
            )
        if any(not item for item in fixtures) or len(set(fixtures)) != len(fixtures):
            raise ValueError("fixture IDs must be non-empty and unique")
        parameters = dict(self.parameters)
        _validate_json_value(parameters)
        object.__setattr__(
            self,
            "required_message_families",
            families,
        )
        object.__setattr__(self, "required_fields", fields)
        object.__setattr__(
            self,
            "missing_data_requirements",
            missing,
        )
        object.__setattr__(self, "fixture_ids", fixtures)
        object.__setattr__(
            self,
            "parameters",
            _freeze_json_value(parameters),
        )
        _validate_json_value(self.to_dict())

    @property
    def qualified_id(self) -> str:
        """Return the stable function identifier joined with its version."""

        return f"{self.function_id}@{self.version}"

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible function specification."""

        return {
            "schema": "mekai.function_spec/0.1",
            "function_id": self.function_id,
            "version": self.version,
            "qualified_id": self.qualified_id,
            "required_message_families": list(self.required_message_families),
            "required_fields": [item.to_dict() for item in self.required_fields],
            "parameters": _json_copy(self.parameters),
            "method": self.method,
            "basis": self.basis.value,
            "missing_data_requirements": list(self.missing_data_requirements),
            "result_schema": self.result_schema,
            "fixture_ids": list(self.fixture_ids),
        }


@dataclass(frozen=True, slots=True)
class FunctionResult:
    """Deterministic output contract shared by every built-in function."""

    function_id: str
    function_version: str
    status: ResultStatus
    basis: ResultBasis
    scope: ResultScope
    window: EvaluationWindow | None
    coverage: Coverage
    method_version: str
    value: Any = None
    unit: str | None = None
    numerator: Any = None
    denominator: Any = None
    input_references: tuple[InputReference, ...] = ()
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.function_id):
            raise ValueError(f"invalid function_id: {self.function_id!r}")
        if not _SEMVER.fullmatch(self.function_version):
            raise ValueError(f"invalid semantic version: {self.function_version!r}")
        if not self.method_version:
            raise ValueError("method_version is required")
        _validate_json_value(self.value)
        _validate_json_value(self.numerator)
        _validate_json_value(self.denominator)
        if self.status is ResultStatus.NOT_COMPUTABLE:
            if self.value is not None:
                raise ValueError("NOT_COMPUTABLE cannot carry a value")
            if not self.diagnostics:
                raise ValueError("NOT_COMPUTABLE requires a diagnostic reason")
        else:
            if self.value is None:
                raise ValueError("COMPUTED and PARTIAL results require a value")
            if self.window is None:
                raise ValueError("COMPUTED and PARTIAL results require a window")
        if self.window is None and (
            self.status is not ResultStatus.NOT_COMPUTABLE
            or self.coverage.eligible_duration_ns != 0
            or self.coverage.observed_duration_ns != 0
            or self.coverage.missing_intervals
            or self.coverage.known_missing_interval_count != 0
            or self.coverage.missing_interval_details_truncated
        ):
            raise ValueError(
                "an undefined window requires NOT_COMPUTABLE and zero coverage"
            )
        if (
            self.status is ResultStatus.COMPUTED
            and self.coverage.missing_interval_details_truncated
        ):
            raise ValueError("COMPUTED cannot carry truncated coverage detail")
        if self.status is ResultStatus.PARTIAL:
            if (
                not self.coverage.missing_intervals
                and not self.coverage.missing_interval_details_truncated
                and not self.diagnostics
            ):
                raise ValueError("PARTIAL requires missingness or diagnostics")
        references = tuple(self.input_references)
        if len(set(references)) != len(references):
            raise ValueError("input references must be unique")
        object.__setattr__(self, "value", _freeze_json_value(self.value))
        object.__setattr__(
            self,
            "numerator",
            _freeze_json_value(self.numerator),
        )
        object.__setattr__(
            self,
            "denominator",
            _freeze_json_value(self.denominator),
        )
        object.__setattr__(
            self,
            "input_references",
            tuple(
                sorted(
                    references,
                    key=lambda item: (
                        item.source_id,
                        item.input_sha256,
                        item.locator,
                        item.message_family,
                        item.topic or "",
                        item.header_identity or "",
                    ),
                )
            ),
        )
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        _validate_json_value(self.to_dict())

    @property
    def qualified_id(self) -> str:
        """Return the function identifier joined with the producing version."""

        return f"{self.function_id}@{self.function_version}"

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible result representation."""

        return {
            "schema": "mekai.function_result/0.1",
            "qualified_id": self.qualified_id,
            "status": self.status.value,
            "basis": self.basis.value,
            "scope": self.scope.to_dict(),
            "value": _json_copy(self.value),
            "unit": self.unit,
            "window": self.window.to_dict() if self.window is not None else None,
            "numerator": _json_copy(self.numerator),
            "denominator": _json_copy(self.denominator),
            "coverage": self.coverage.to_dict(),
            "method_version": self.method_version,
            "input_references": [item.to_dict() for item in self.input_references],
            "diagnostics": list(self.diagnostics),
        }

    def to_json(self) -> str:
        """Serialize the result as canonical compact JSON."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def _validate_json_value(value: Any) -> None:
    """Reject values that cannot be represented safely in strict JSON."""

    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if contains_invalid_unicode_scalar(value):
            raise ValueError(
                "JSON text contains an invalid Unicode scalar value"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity are not valid result values")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("JSON object keys must be strings")
            _validate_json_value(key)
            _validate_json_value(item)
        return
    raise ValueError(f"value is not JSON-compatible: {type(value).__name__}")


def _freeze_json_value(value: Any) -> Any:
    """Recursively copy JSON-like data into immutable containers."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(item) for item in value)
    return value


def _json_copy(value: Any) -> Any:
    """Convert frozen JSON-like data back to mutable serialization values."""

    if isinstance(value, Mapping):
        return {key: _json_copy(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_copy(item) for item in value]
    return value
