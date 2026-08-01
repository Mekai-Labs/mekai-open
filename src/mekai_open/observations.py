"""Immutable transport-neutral facts for recorded VDA analysis."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from .json_safety import contains_invalid_unicode_scalar
from .source_ids import validate_source_id
from .vda_schemas import FrozenJsonValue, VdaMessageFamily

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_SIGNED_64 = (1 << 63) - 1
_MAX_LOCATOR_CHARACTERS = 256
_MAX_DIAGNOSTIC_CODE_CHARACTERS = 128
MAX_ROBOT_TARGET_SUBJECT_ID_CHARACTERS = 128
MAX_ROBOT_TARGET_IDENTITY_CHARACTERS = 4_096


class CaptureBoundaryKind(StrEnum):
    """Identify one accepted capture-level boundary."""

    START = "capture_start"
    END = "capture_end"


class SessionBoundaryKind(StrEnum):
    """Identify one accepted collector-session boundary."""

    START = "session_start"
    END = "session_end"


@dataclass(frozen=True, slots=True, order=True)
class RobotIdentity:
    """Preserve the exact manufacturer and serial number reported by VDA."""

    manufacturer: str
    serial_number: str

    def __post_init__(self) -> None:
        if contains_invalid_unicode_scalar(self.manufacturer) or (
            contains_invalid_unicode_scalar(self.serial_number)
        ):
            raise ValueError("robot identity contains invalid Unicode")

    def to_dict(self) -> dict[str, str]:
        """Return the VDA-named structured robot identity."""

        return {
            "manufacturer": self.manufacturer,
            "serialNumber": self.serial_number,
        }


@dataclass(frozen=True, slots=True)
class RobotTarget:
    """Bind a stable caller subject ID to one exact reported robot identity."""

    subject_id: str
    robot_identity: RobotIdentity

    def __post_init__(self) -> None:
        if (
            not self.subject_id
            or len(self.subject_id) > MAX_ROBOT_TARGET_SUBJECT_ID_CHARACTERS
            or contains_invalid_unicode_scalar(self.subject_id)
        ):
            raise ValueError("robot target subject ID must be bounded and non-empty")
        if (
            len(self.robot_identity.manufacturer)
            > MAX_ROBOT_TARGET_IDENTITY_CHARACTERS
            or len(self.robot_identity.serial_number)
            > MAX_ROBOT_TARGET_IDENTITY_CHARACTERS
        ):
            raise ValueError("robot target identity exceeds the retained identity limit")


@dataclass(frozen=True, slots=True)
class NormalizedVdaObservation:
    """Represent one capture-accepted and structurally valid VDA message."""

    source_id: str
    locator: str
    observation_time_ns: int
    continuity_epoch: int
    message_family: VdaMessageFamily
    topic: str | None
    robot_identity: RobotIdentity
    header_id: int
    source_timestamp: str
    retained: bool | None
    producer_duplicate: bool | None
    payload_sha256: str
    validated_payload: Mapping[str, FrozenJsonValue]
    capture_diagnostic_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_common(self.source_id, self.locator, self.observation_time_ns)
        _validate_non_negative_64(self.continuity_epoch, "continuity_epoch")
        if isinstance(self.header_id, bool) or not isinstance(self.header_id, int):
            raise ValueError("header_id must be an integer")
        if self.topic is not None and not self.topic:
            raise ValueError("topic cannot be empty when present")
        if not self.source_timestamp:
            raise ValueError("source_timestamp cannot be empty")
        if not _SHA256.fullmatch(self.payload_sha256):
            raise ValueError("payload_sha256 must be lowercase SHA-256")
        if not isinstance(self.validated_payload, Mapping):
            raise ValueError("validated_payload must be a JSON object")
        _validate_diagnostic_codes(self.capture_diagnostic_codes)


@dataclass(frozen=True, slots=True)
class MessageDiscontinuityObservation:
    """Represent one typed message excluded by capture or VDA validation."""

    source_id: str
    locator: str
    observation_time_ns: int
    continuity_epoch: int | None
    message_family: VdaMessageFamily
    topic: str
    payload_sha256: str
    capture_accepted: bool
    vda_valid: bool
    capture_diagnostic_codes: tuple[str, ...]
    vda_diagnostic_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_common(self.source_id, self.locator, self.observation_time_ns)
        if self.capture_accepted and self.vda_valid:
            raise ValueError("eligible messages are valid observations")
        if self.continuity_epoch is not None:
            _validate_non_negative_64(self.continuity_epoch, "continuity_epoch")
        if self.capture_accepted != (self.continuity_epoch is not None):
            raise ValueError("accepted message discontinuities require an epoch")
        if not self.topic:
            raise ValueError("message discontinuity topic cannot be empty")
        if not _SHA256.fullmatch(self.payload_sha256):
            raise ValueError("payload_sha256 must be lowercase SHA-256")
        _validate_diagnostic_codes(self.capture_diagnostic_codes)
        _validate_diagnostic_codes(self.vda_diagnostic_codes)


@dataclass(frozen=True, slots=True)
class CaptureBoundaryObservation:
    """Represent one accepted capture start or end observation."""

    source_id: str
    locator: str
    observation_time_ns: int
    sequence: int
    kind: CaptureBoundaryKind
    declared_complete: bool | None
    capture_diagnostic_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_common(self.source_id, self.locator, self.observation_time_ns)
        _validate_non_negative_64(self.sequence, "sequence")
        if self.kind is CaptureBoundaryKind.START:
            if self.declared_complete is not None:
                raise ValueError("capture_start cannot declare completeness")
        elif self.declared_complete is None:
            raise ValueError("capture_end must declare completeness")
        _validate_diagnostic_codes(self.capture_diagnostic_codes)


@dataclass(frozen=True, slots=True)
class CollectorSessionObservation:
    """Represent one accepted collector-session epoch boundary."""

    source_id: str
    locator: str
    observation_time_ns: int
    sequence: int
    kind: SessionBoundaryKind
    producer_session_id: str
    continuity_epoch: int
    capture_diagnostic_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_common(self.source_id, self.locator, self.observation_time_ns)
        _validate_non_negative_64(self.sequence, "sequence")
        _validate_non_negative_64(self.continuity_epoch, "continuity_epoch")
        if not self.producer_session_id:
            raise ValueError("producer_session_id cannot be empty")
        if (
            self.kind is SessionBoundaryKind.START
            and self.continuity_epoch != self.sequence
        ):
            raise ValueError("session_start must identify its own continuity epoch")
        _validate_diagnostic_codes(self.capture_diagnostic_codes)


@dataclass(frozen=True, slots=True)
class CollectorDropObservation:
    """Represent one accepted explicit collector drop without a duration."""

    source_id: str
    locator: str
    observation_time_ns: int
    sequence: int
    continuity_epoch: int
    producer_session_id: str
    drop_count: int
    drop_reason: str
    capture_diagnostic_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _validate_common(self.source_id, self.locator, self.observation_time_ns)
        _validate_non_negative_64(self.sequence, "sequence")
        _validate_non_negative_64(self.continuity_epoch, "continuity_epoch")
        if not self.producer_session_id or not self.drop_reason:
            raise ValueError("drop session label and reason cannot be empty")
        if (
            isinstance(self.drop_count, bool)
            or not isinstance(self.drop_count, int)
            or not 1 <= self.drop_count <= _MAX_SIGNED_64
        ):
            raise ValueError("drop_count must be a positive signed 64-bit integer")
        _validate_diagnostic_codes(self.capture_diagnostic_codes)


@dataclass(frozen=True, slots=True)
class CaptureDiscontinuityObservation:
    """Represent a rejected or untyped capture record as a health fact."""

    source_id: str
    locator: str
    observation_time_ns: int | None
    record_kind: str | None
    diagnostic_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        _validate_locator(self.locator)
        if self.observation_time_ns is not None:
            _validate_non_negative_64(
                self.observation_time_ns, "observation_time_ns"
            )
        if self.record_kind is not None and not self.record_kind:
            raise ValueError("record_kind cannot be empty when present")
        if not self.diagnostic_codes:
            raise ValueError("capture discontinuity requires diagnostics")
        _validate_diagnostic_codes(self.diagnostic_codes)


@dataclass(frozen=True, slots=True)
class InputMutationObservation:
    """Represent failure of the recorded input mutation-verification boundary."""

    source_id: str

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)


@dataclass(frozen=True, slots=True)
class NormalizedCaptureSummary:
    """Carry verified capture totals and completion state into analysis."""

    source_id: str
    input_sha256: str
    physical_record_count: int
    accepted_record_count: int
    declared_complete: bool | None
    structurally_compromised: bool
    verified_unchanged: bool
    complete: bool
    diagnostic_codes: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        if not _SHA256.fullmatch(self.input_sha256):
            raise ValueError("input_sha256 must be lowercase SHA-256")
        _validate_non_negative_64(
            self.physical_record_count, "physical_record_count"
        )
        _validate_non_negative_64(
            self.accepted_record_count, "accepted_record_count"
        )
        if self.accepted_record_count > self.physical_record_count:
            raise ValueError("accepted records cannot exceed physical records")
        for code, locator in self.diagnostic_codes:
            _validate_diagnostic_codes((code,))
            _validate_locator(locator)


type RecordedObservation = (
    NormalizedVdaObservation
    | MessageDiscontinuityObservation
    | CaptureBoundaryObservation
    | CollectorSessionObservation
    | CollectorDropObservation
    | CaptureDiscontinuityObservation
    | InputMutationObservation
)


def _validate_common(
    source_id: str, locator: str, observation_time_ns: int
) -> None:
    """Validate fields shared by timestamped normalized observations."""

    validate_source_id(source_id)
    _validate_locator(locator)
    _validate_non_negative_64(observation_time_ns, "observation_time_ns")


def _validate_non_negative_64(value: int, name: str) -> None:
    """Validate one non-negative signed 64-bit integer."""

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_SIGNED_64
    ):
        raise ValueError(f"{name} must be a non-negative signed 64-bit integer")


def _validate_locator(locator: str) -> None:
    """Reject empty, control-bearing, absolute, or oversized source locators."""

    if (
        not locator
        or len(locator) > _MAX_LOCATOR_CHARACTERS
        or locator.startswith(("/", "\\"))
        or any(ord(character) < 0x20 for character in locator)
    ):
        raise ValueError("locator must be bounded, portable, and non-empty")


def _validate_diagnostic_codes(codes: tuple[str, ...]) -> None:
    """Validate bounded symbolic diagnostic-code tuples."""

    for code in codes:
        if (
            not code
            or len(code) > _MAX_DIAGNOSTIC_CODE_CHARACTERS
            or not code.replace("_", "").isalnum()
        ):
            raise ValueError("diagnostic code is not a bounded symbol")
