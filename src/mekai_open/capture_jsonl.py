"""Stream and validate recorded Mekai Capture JSONL files."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO, Self

from .input_fingerprint import (
    InputChangedError,
    InputFingerprint,
    InputFingerprintError,
    fingerprint_regular_file,
    open_verified_regular_file,
    verify_unchanged,
)
from .json_safety import (
    StrictJsonDecodingError,
    bounded_json_pointer,
    decode_strict_json,
)
from .source_ids import validate_source_id
from .vda_schemas import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_MESSAGE_BYTES_CEILING,
    ValidatedVdaMessage,
    ValidationDiagnostic,
    VdaMessageFamily,
    VdaPayloadValidationError,
    validate_message_byte_limit,
    validate_vda_payload,
)

CAPTURE_SCHEMA_ID = "mekai.capture_record/0.1"
CAPTURE_ENVELOPE_HEADROOM_BYTES = 64 * 1024
MAX_CAPTURE_SESSION_ID_CHARACTERS = 256
MAX_CAPTURE_TOPIC_CHARACTERS = 4096
MAX_CAPTURE_DROP_REASON_CHARACTERS = 1024

_MAX_SIGNED_64 = (1 << 63) - 1
_MAX_CAPTURE_DIAGNOSTICS = 256
_MAX_DIAGNOSTIC_EXPLANATION_CHARACTERS = 256
_MAX_DIAGNOSTIC_PATH_CHARACTERS = 512
_MAX_DIAGNOSTIC_LOCATOR_CHARACTERS = 64
_DRAIN_CHUNK_BYTES = 64 * 1024
_MAX_BASE64_CHARACTERS = 4 * ((MAX_MESSAGE_BYTES_CEILING + 2) // 3)


class CaptureRecordKind(StrEnum):
    """Identify one supported Mekai Capture record kind."""

    CAPTURE_START = "capture_start"
    SESSION_START = "session_start"
    MESSAGE = "message"
    SESSION_END = "session_end"
    DROP = "drop"
    CAPTURE_END = "capture_end"


class CaptureDiagnosticCode(StrEnum):
    """Classify bounded capture-envelope and lifecycle failures."""

    EMPTY_RECORD = "EMPTY_RECORD"
    RECORD_TOO_LARGE = "RECORD_TOO_LARGE"
    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_UNICODE = "INVALID_UNICODE"
    MALFORMED_JSON = "MALFORMED_JSON"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    NON_FINITE_NUMBER = "NON_FINITE_NUMBER"
    NESTING_TOO_DEEP = "NESTING_TOO_DEEP"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    ENVELOPE_VIOLATION = "ENVELOPE_VIOLATION"
    INVALID_BASE64 = "INVALID_BASE64"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    SEQUENCE_MISMATCH = "SEQUENCE_MISMATCH"
    CAPTURE_START_NOT_FIRST = "CAPTURE_START_NOT_FIRST"
    CAPTURE_START_REQUIRED = "CAPTURE_START_REQUIRED"
    DUPLICATE_CAPTURE_START = "DUPLICATE_CAPTURE_START"
    SESSION_ALREADY_ACTIVE = "SESSION_ALREADY_ACTIVE"
    SESSION_REQUIRED = "SESSION_REQUIRED"
    SESSION_ID_MISMATCH = "SESSION_ID_MISMATCH"
    CAPTURE_END_WITH_ACTIVE_SESSION = "CAPTURE_END_WITH_ACTIVE_SESSION"
    DUPLICATE_CAPTURE_END = "DUPLICATE_CAPTURE_END"
    RECORD_AFTER_CAPTURE_END = "RECORD_AFTER_CAPTURE_END"
    MONOTONIC_TIME_REGRESSION = "MONOTONIC_TIME_REGRESSION"
    UTC_TIME_REGRESSION = "UTC_TIME_REGRESSION"
    CAPTURE_DECLARED_INCOMPLETE = "CAPTURE_DECLARED_INCOMPLETE"
    MISSING_CAPTURE_START = "MISSING_CAPTURE_START"
    MISSING_CAPTURE_END = "MISSING_CAPTURE_END"
    SESSION_LEFT_OPEN = "SESSION_LEFT_OPEN"
    DIAGNOSTICS_TRUNCATED = "DIAGNOSTICS_TRUNCATED"


@dataclass(frozen=True, slots=True)
class CaptureDiagnostic:
    """Describe one portable bounded capture failure or timing warning."""

    code: CaptureDiagnosticCode
    locator: str
    instance_path: str
    explanation: str

    def __post_init__(self) -> None:
        if len(self.locator) > _MAX_DIAGNOSTIC_LOCATOR_CHARACTERS:
            raise ValueError("capture diagnostic locator exceeds the safe bound")
        if self.locator != "eof" and not self.locator.startswith("line:"):
            raise ValueError("capture diagnostic locator must be portable")
        if len(self.instance_path) > _MAX_DIAGNOSTIC_PATH_CHARACTERS:
            raise ValueError("capture diagnostic path exceeds the safe bound")
        if self.instance_path and not self.instance_path.startswith("/"):
            raise ValueError("capture diagnostic path must be a JSON pointer")
        if len(self.explanation) > _MAX_DIAGNOSTIC_EXPLANATION_CHARACTERS:
            raise ValueError("capture diagnostic explanation exceeds the safe bound")


@dataclass(frozen=True, slots=True)
class CaptureControlRecord:
    """Represent an accepted or diagnosed capture boundary record."""

    source_id: str
    locator: str
    kind: CaptureRecordKind
    sequence: int
    observation_time_ns: int
    receive_monotonic_ns: int | None
    capture_accepted: bool
    capture_diagnostics: tuple[CaptureDiagnostic, ...]
    complete: bool | None

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)


@dataclass(frozen=True, slots=True)
class CaptureSessionRecord:
    """Represent a collector-session boundary and its derived active epoch."""

    source_id: str
    locator: str
    kind: CaptureRecordKind
    sequence: int
    observation_time_ns: int
    receive_monotonic_ns: int | None
    capture_accepted: bool
    capture_diagnostics: tuple[CaptureDiagnostic, ...]
    collector_session_id: str
    collector_session_start_sequence: int | None

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        _validate_collector_session_epoch(
            self.capture_accepted, self.collector_session_start_sequence
        )
        if (
            self.capture_accepted
            and self.kind is CaptureRecordKind.SESSION_START
            and self.collector_session_start_sequence != self.sequence
        ):
            raise ValueError("accepted session_start must identify its own sequence")


@dataclass(frozen=True, slots=True)
class CaptureDropRecord:
    """Represent an explicit collector drop fact within its active epoch."""

    source_id: str
    locator: str
    kind: CaptureRecordKind
    sequence: int
    observation_time_ns: int
    receive_monotonic_ns: int | None
    capture_accepted: bool
    capture_diagnostics: tuple[CaptureDiagnostic, ...]
    collector_session_id: str
    collector_session_start_sequence: int | None
    drop_count: int
    drop_reason: str

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        _validate_collector_session_epoch(
            self.capture_accepted, self.collector_session_start_sequence
        )
        if (
            isinstance(self.drop_count, bool)
            or not isinstance(self.drop_count, int)
            or not 1 <= self.drop_count <= _MAX_SIGNED_64
        ):
            raise ValueError("drop_count must be a positive signed 64-bit integer")


@dataclass(frozen=True, slots=True)
class CaptureMessageRecord:
    """Represent exact message, session, transport, and VDA validation facts."""

    source_id: str
    locator: str
    kind: CaptureRecordKind
    sequence: int
    observation_time_ns: int
    receive_monotonic_ns: int | None
    capture_accepted: bool
    capture_diagnostics: tuple[CaptureDiagnostic, ...]
    collector_session_id: str
    collector_session_start_sequence: int | None
    message_family: VdaMessageFamily
    topic: str
    qos: int
    retained: bool
    duplicate: bool
    raw_payload: bytes
    payload_sha256: str
    validated_message: ValidatedVdaMessage | None
    validation_diagnostics: tuple[ValidationDiagnostic, ...]

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        _validate_collector_session_epoch(
            self.capture_accepted, self.collector_session_start_sequence
        )
        if hashlib.sha256(self.raw_payload).hexdigest() != self.payload_sha256:
            raise ValueError("capture message payload digest is inconsistent")
        has_message = self.validated_message is not None
        has_diagnostics = bool(self.validation_diagnostics)
        if has_message == has_diagnostics:
            raise ValueError("capture message requires one VDA validation outcome")

    @property
    def eligible_for_functions(self) -> bool:
        """Return whether product metric functions may consume this message."""

        return self.capture_accepted and self.validated_message is not None


@dataclass(frozen=True, slots=True)
class InvalidCaptureRecord:
    """Represent one physical line rejected before a typed capture fact exists."""

    source_id: str
    locator: str
    diagnostics: tuple[CaptureDiagnostic, ...]

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)


@dataclass(frozen=True, slots=True)
class CaptureReadSummary:
    """Describe structural completion after exhausted, mutation-verified reading.

    ``accepted_record_count`` counts records accepted by the capture envelope
    and lifecycle boundary, including messages whose VDA payload is invalid.
    ``complete`` describes the declared and verified capture stream; it does
    not assert that every VDA message is valid or any metric is computable.
    """

    source_id: str
    input_sha256: str
    physical_record_count: int
    accepted_record_count: int
    declared_complete: bool | None
    structurally_compromised: bool
    verified_unchanged: bool
    complete: bool
    diagnostics: tuple[CaptureDiagnostic, ...]

    def __post_init__(self) -> None:
        validate_source_id(self.source_id)
        if self.complete and (
            not self.verified_unchanged
            or self.structurally_compromised
            or self.declared_complete is not True
        ):
            raise ValueError("complete capture summary is internally inconsistent")


class CaptureInputError(ValueError):
    """Report an unsafe, unreadable, or unsupported capture input."""


class CaptureReaderArgumentError(ValueError):
    """Report an unsupported capture-reader caller argument."""


class CaptureReaderStateError(RuntimeError):
    """Report use of a capture reader outside its context or before exhaustion."""


type CaptureReadItem = (
    CaptureControlRecord
    | CaptureSessionRecord
    | CaptureDropRecord
    | CaptureMessageRecord
    | InvalidCaptureRecord
)


_COMMON_REQUIRED = frozenset(
    {"schema", "kind", "sequence", "receive_time_ns"}
)
_COMMON_OPTIONAL = frozenset({"receive_monotonic_ns"})
_KIND_REQUIRED: Mapping[CaptureRecordKind, frozenset[str]] = {
    CaptureRecordKind.CAPTURE_START: frozenset(),
    CaptureRecordKind.SESSION_START: frozenset({"collector_session_id"}),
    CaptureRecordKind.MESSAGE: frozenset(
        {
            "collector_session_id",
            "message_family",
            "topic",
            "qos",
            "retained",
            "duplicate",
            "payload_base64",
        }
    ),
    CaptureRecordKind.SESSION_END: frozenset({"collector_session_id"}),
    CaptureRecordKind.DROP: frozenset(
        {"collector_session_id", "drop_count", "drop_reason"}
    ),
    CaptureRecordKind.CAPTURE_END: frozenset({"complete"}),
}
_NON_COMPROMISING_CODES = frozenset(
    {
        CaptureDiagnosticCode.UTC_TIME_REGRESSION,
        CaptureDiagnosticCode.CAPTURE_DECLARED_INCOMPLETE,
    }
)


def _validate_collector_session_epoch(
    capture_accepted: bool, collector_session_start_sequence: int | None
) -> None:
    """Enforce the session-epoch invariant on immutable typed records."""

    if collector_session_start_sequence is not None and (
        isinstance(collector_session_start_sequence, bool)
        or not isinstance(collector_session_start_sequence, int)
        or not 0 <= collector_session_start_sequence <= _MAX_SIGNED_64
    ):
        raise ValueError(
            "collector_session_start_sequence must be a non-negative "
            "signed 64-bit integer or None"
        )
    if capture_accepted != (collector_session_start_sequence is not None):
        raise ValueError(
            "accepted session-scoped records require a collector session epoch"
        )


def capture_record_byte_limit(max_message_bytes: int) -> int:
    """Return the maximum physical JSONL record size including one terminator."""

    validate_message_byte_limit(max_message_bytes)
    base64_capacity = 4 * ((max_message_bytes + 2) // 3)
    return base64_capacity + CAPTURE_ENVELOPE_HEADROOM_BYTES + 1


class CaptureReader(Iterator[CaptureReadItem]):
    """Stream one fingerprinted capture and finalize only after safe exhaustion."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        source_id: str,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str):
            raise CaptureReaderArgumentError("capture path must be text")
        try:
            validate_source_id(source_id)
        except ValueError:
            raise CaptureReaderArgumentError(
                "source_id does not satisfy the portable identifier contract"
            ) from None
        validate_message_byte_limit(max_message_bytes)
        self._path = raw_path
        self._source_id = source_id
        self._max_message_bytes = max_message_bytes
        self._record_byte_limit = capture_record_byte_limit(max_message_bytes)
        self._fingerprint: InputFingerprint | None = None
        self._stream: BinaryIO | None = None
        self._closed = False
        self._summary: CaptureReadSummary | None = None
        self._line_number = 0
        self._accepted_record_count = 0
        self._expected_sequence = 0
        self._maximum_receive_time_ns: int | None = None
        self._maximum_monotonic_ns: int | None = None
        self._saw_structural_record = False
        self._capture_start_seen = False
        self._capture_started = False
        self._capture_end_seen = False
        self._declared_complete: bool | None = None
        self._active_session_id: str | None = None
        self._active_session_start_sequence: int | None = None
        self._structurally_compromised = False
        self._diagnostics: list[CaptureDiagnostic] = []

    def __enter__(self) -> Self:
        """Fingerprint and safely open the capture for streaming iteration."""

        if self._stream is not None or self._closed:
            raise CaptureReaderStateError("capture reader cannot be entered twice")
        try:
            fingerprint = fingerprint_regular_file(self._path)
            stream = open_verified_regular_file(fingerprint)
        except InputChangedError:
            raise InputChangedError(
                "INPUT_CHANGED: capture input changed before reading"
            ) from None
        except (InputFingerprintError, OSError):
            raise CaptureInputError(
                "capture input must be one readable regular non-symlink file"
            ) from None
        self._fingerprint = fingerprint
        self._stream = stream
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object | None,
    ) -> None:
        """Close the descriptor without finalizing an incompletely consumed read."""

        self.close()

    def __iter__(self) -> Self:
        """Return this context-managed streaming iterator."""

        return self

    def __next__(self) -> CaptureReadItem:
        """Read, validate, and return the next bounded physical capture record."""

        if self._summary is not None:
            raise StopIteration
        if self._stream is None or self._closed:
            raise CaptureReaderStateError(
                "capture reader must be iterated inside its active context"
            )
        try:
            raw_line = self._stream.readline(self._record_byte_limit + 1)
        except OSError:
            self.close()
            raise CaptureInputError("capture input could not be read safely") from None
        if not raw_line:
            self._finalize()
            raise StopIteration

        self._line_number += 1
        locator = f"line:{self._line_number}"
        if len(raw_line) > self._record_byte_limit:
            self._drain_oversized_line(raw_line)
            diagnostic = _diagnostic(
                CaptureDiagnosticCode.RECORD_TOO_LARGE,
                locator,
                (),
                "Capture record exceeds the configured physical line limit.",
            )
            self._record_diagnostics((diagnostic,))
            return InvalidCaptureRecord(
                self._source_id, locator, (diagnostic,)
            )

        line = _remove_line_terminator(raw_line)
        if not line:
            diagnostic = _diagnostic(
                CaptureDiagnosticCode.EMPTY_RECORD,
                locator,
                (),
                "Capture JSONL records cannot be blank.",
            )
            self._record_diagnostics((diagnostic,))
            return InvalidCaptureRecord(
                self._source_id, locator, (diagnostic,)
            )
        return self._decode_record(line, locator)

    @property
    def summary(self) -> CaptureReadSummary:
        """Return the final summary only after complete verified exhaustion."""

        if self._summary is None:
            raise CaptureReaderStateError(
                "capture summary is unavailable before verified exhaustion"
            )
        return self._summary

    def close(self) -> None:
        """Close an open reader without asserting successful exhaustion."""

        if self._stream is not None:
            try:
                self._stream.close()
            except OSError:
                pass
            self._stream = None
        self._closed = True

    def _drain_oversized_line(self, first_chunk: bytes) -> None:
        """Discard only the remainder of one oversized line in bounded chunks."""

        if first_chunk.endswith(b"\n"):
            return
        assert self._stream is not None
        while True:
            try:
                chunk = self._stream.readline(_DRAIN_CHUNK_BYTES)
            except OSError:
                self.close()
                raise CaptureInputError(
                    "capture input could not be read safely"
                ) from None
            if not chunk or chunk.endswith(b"\n"):
                return

    def _decode_record(self, line: bytes, locator: str) -> CaptureReadItem:
        """Decode one bounded line and route it through envelope processing."""

        try:
            value = decode_strict_json(line)
        except StrictJsonDecodingError as error:
            diagnostics = _ordered_capture_diagnostics(
                tuple(
                    CaptureDiagnostic(
                        code=CaptureDiagnosticCode(item.code.value),
                        locator=locator,
                        instance_path=item.instance_path,
                        explanation=item.explanation,
                    )
                    for item in error.diagnostics
                )
            )
            self._record_diagnostics(diagnostics)
            return InvalidCaptureRecord(
                self._source_id, locator, diagnostics
            )

        diagnostics = _validate_envelope(value, locator)
        if diagnostics:
            self._record_diagnostics(diagnostics)
            return InvalidCaptureRecord(
                self._source_id, locator, diagnostics
            )
        assert isinstance(value, dict)
        return self._process_envelope(value, locator)

    def _process_envelope(
        self, envelope: dict[str, object], locator: str
    ) -> CaptureReadItem:
        """Apply ordering, lifecycle, payload, and VDA validation boundaries."""

        kind = CaptureRecordKind(envelope["kind"])
        if self._capture_end_seen:
            diagnostics = [
                _diagnostic(
                    CaptureDiagnosticCode.RECORD_AFTER_CAPTURE_END,
                    locator,
                    (),
                    "Capture records after capture_end are invalid.",
                )
            ]
            if kind is CaptureRecordKind.CAPTURE_END:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.DUPLICATE_CAPTURE_END,
                        locator,
                        ("kind",),
                        "capture_end may appear at most once.",
                    )
                )
            ordered = _ordered_capture_diagnostics(diagnostics)
            self._record_diagnostics(ordered)
            return InvalidCaptureRecord(self._source_id, locator, ordered)

        diagnostics: list[CaptureDiagnostic] = []
        diagnostics.extend(self._time_diagnostics(envelope, locator))
        sequence_ok, sequence_diagnostic = self._check_sequence(
            int(envelope["sequence"]), locator
        )
        if sequence_diagnostic is not None:
            diagnostics.append(sequence_diagnostic)
        transition_ready = sequence_ok and not any(
            _is_compromising(item.code) for item in diagnostics
        )
        active_session_start_sequence_before = (
            self._active_session_start_sequence
        )
        diagnostics.extend(
            self._lifecycle_diagnostics(
                envelope, kind, locator, transition_ready
            )
        )
        ordered = _ordered_capture_diagnostics(diagnostics)
        capture_accepted = not any(
            _is_compromising(item.code) for item in ordered
        )
        collector_session_start_sequence: int | None = None
        if capture_accepted:
            if kind in {
                CaptureRecordKind.SESSION_START,
                CaptureRecordKind.MESSAGE,
                CaptureRecordKind.DROP,
            }:
                collector_session_start_sequence = (
                    self._active_session_start_sequence
                )
            elif kind is CaptureRecordKind.SESSION_END:
                collector_session_start_sequence = (
                    active_session_start_sequence_before
                )
        self._record_diagnostics(ordered)

        common = {
            "source_id": self._source_id,
            "locator": locator,
            "kind": kind,
            "sequence": int(envelope["sequence"]),
            "observation_time_ns": int(envelope["receive_time_ns"]),
            "receive_monotonic_ns": _optional_int(
                envelope.get("receive_monotonic_ns")
            ),
            "capture_accepted": capture_accepted,
            "capture_diagnostics": ordered,
        }
        if kind in {
            CaptureRecordKind.CAPTURE_START,
            CaptureRecordKind.CAPTURE_END,
        }:
            if capture_accepted:
                self._accepted_record_count += 1
            return CaptureControlRecord(
                **common,
                complete=(
                    bool(envelope["complete"])
                    if kind is CaptureRecordKind.CAPTURE_END
                    else None
                ),
            )
        if kind in {
            CaptureRecordKind.SESSION_START,
            CaptureRecordKind.SESSION_END,
        }:
            if capture_accepted:
                self._accepted_record_count += 1
            return CaptureSessionRecord(
                **common,
                collector_session_id=str(envelope["collector_session_id"]),
                collector_session_start_sequence=(
                    collector_session_start_sequence
                ),
            )
        if kind is CaptureRecordKind.DROP:
            if capture_accepted:
                self._accepted_record_count += 1
            return CaptureDropRecord(
                **common,
                collector_session_id=str(envelope["collector_session_id"]),
                collector_session_start_sequence=(
                    collector_session_start_sequence
                ),
                drop_count=int(envelope["drop_count"]),
                drop_reason=str(envelope["drop_reason"]),
            )
        return self._message_record(
            envelope, common, locator, collector_session_start_sequence
        )

    def _message_record(
        self,
        envelope: dict[str, object],
        common: dict[str, object],
        locator: str,
        collector_session_start_sequence: int | None,
    ) -> CaptureReadItem:
        """Decode exact message bytes and apply the existing VDA boundary."""

        payload, diagnostic = _decode_payload_base64(
            str(envelope["payload_base64"]),
            locator,
            self._max_message_bytes,
        )
        if diagnostic is not None:
            existing = tuple(common["capture_diagnostics"])
            diagnostics = _ordered_capture_diagnostics(
                (*existing, diagnostic)
            )
            self._record_diagnostics((diagnostic,))
            return InvalidCaptureRecord(
                self._source_id, locator, diagnostics
            )
        assert payload is not None
        digest = hashlib.sha256(payload).hexdigest()
        family = VdaMessageFamily(str(envelope["message_family"]))
        validated_message: ValidatedVdaMessage | None = None
        validation_diagnostics: tuple[ValidationDiagnostic, ...] = ()
        if bool(common["capture_accepted"]):
            self._accepted_record_count += 1
        try:
            validated_message = validate_vda_payload(
                payload,
                family,
                max_message_bytes=self._max_message_bytes,
            )
        except VdaPayloadValidationError as error:
            validation_diagnostics = error.diagnostics
        return CaptureMessageRecord(
            **common,
            collector_session_id=str(envelope["collector_session_id"]),
            collector_session_start_sequence=collector_session_start_sequence,
            message_family=family,
            topic=str(envelope["topic"]),
            qos=int(envelope["qos"]),
            retained=bool(envelope["retained"]),
            duplicate=bool(envelope["duplicate"]),
            raw_payload=payload,
            payload_sha256=digest,
            validated_message=validated_message,
            validation_diagnostics=validation_diagnostics,
        )

    def _time_diagnostics(
        self, envelope: dict[str, object], locator: str
    ) -> tuple[CaptureDiagnostic, ...]:
        """Diagnose timestamp regressions while preserving reported values."""

        diagnostics: list[CaptureDiagnostic] = []
        receive_time = int(envelope["receive_time_ns"])
        if (
            self._maximum_receive_time_ns is not None
            and receive_time < self._maximum_receive_time_ns
        ):
            diagnostics.append(
                _diagnostic(
                    CaptureDiagnosticCode.UTC_TIME_REGRESSION,
                    locator,
                    ("receive_time_ns",),
                    "UTC receive time regressed; the reported value was preserved.",
                )
            )
        self._maximum_receive_time_ns = max(
            receive_time,
            self._maximum_receive_time_ns
            if self._maximum_receive_time_ns is not None
            else receive_time,
        )

        monotonic = _optional_int(envelope.get("receive_monotonic_ns"))
        if monotonic is not None:
            if (
                self._maximum_monotonic_ns is not None
                and monotonic < self._maximum_monotonic_ns
            ):
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.MONOTONIC_TIME_REGRESSION,
                        locator,
                        ("receive_monotonic_ns",),
                        "Capture monotonic time cannot regress.",
                    )
                )
            self._maximum_monotonic_ns = max(
                monotonic,
                self._maximum_monotonic_ns
                if self._maximum_monotonic_ns is not None
                else monotonic,
            )
        return tuple(diagnostics)

    def _check_sequence(
        self, sequence: int, locator: str
    ) -> tuple[bool, CaptureDiagnostic | None]:
        """Check contiguous zero-based sequence and advance deterministic recovery."""

        if sequence == self._expected_sequence:
            self._expected_sequence += 1
            return True, None
        diagnostic = _diagnostic(
            CaptureDiagnosticCode.SEQUENCE_MISMATCH,
            locator,
            ("sequence",),
            "Capture sequence must start at zero and remain contiguous.",
        )
        if sequence > self._expected_sequence:
            self._expected_sequence = sequence + 1
        return False, diagnostic

    def _lifecycle_diagnostics(
        self,
        envelope: dict[str, object],
        kind: CaptureRecordKind,
        locator: str,
        transition_ready: bool,
    ) -> tuple[CaptureDiagnostic, ...]:
        """Check and update deterministic capture and collector-session state."""

        diagnostics: list[CaptureDiagnostic] = []
        if kind is CaptureRecordKind.CAPTURE_START:
            if self._capture_start_seen:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.DUPLICATE_CAPTURE_START,
                        locator,
                        ("kind",),
                        "capture_start may appear exactly once.",
                    )
                )
            if self._saw_structural_record:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.CAPTURE_START_NOT_FIRST,
                        locator,
                        ("kind",),
                        "capture_start must be the first structural record.",
                    )
                )
            self._capture_start_seen = True
            if transition_ready and not diagnostics:
                self._capture_started = True
        else:
            if not self._capture_started:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.CAPTURE_START_REQUIRED,
                        locator,
                        ("kind",),
                        "A valid capture_start record is required first.",
                    )
                )

        lifecycle_ready = transition_ready and self._capture_started
        if kind is CaptureRecordKind.SESSION_START:
            if self._active_session_id is not None:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.SESSION_ALREADY_ACTIVE,
                        locator,
                        ("collector_session_id",),
                        "Only one collector session may be active.",
                    )
                )
            elif lifecycle_ready:
                self._active_session_id = str(envelope["collector_session_id"])
                self._active_session_start_sequence = int(envelope["sequence"])
        elif kind in {CaptureRecordKind.MESSAGE, CaptureRecordKind.DROP}:
            session_id = str(envelope["collector_session_id"])
            if self._active_session_id is None:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.SESSION_REQUIRED,
                        locator,
                        ("collector_session_id",),
                        "Message and drop records require an active session.",
                    )
                )
            elif session_id != self._active_session_id:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.SESSION_ID_MISMATCH,
                        locator,
                        ("collector_session_id",),
                        "Record session ID must match the active session.",
                    )
                )
        elif kind is CaptureRecordKind.SESSION_END:
            session_id = str(envelope["collector_session_id"])
            if self._active_session_id is None:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.SESSION_REQUIRED,
                        locator,
                        ("collector_session_id",),
                        "session_end requires an active collector session.",
                    )
                )
            elif session_id != self._active_session_id:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.SESSION_ID_MISMATCH,
                        locator,
                        ("collector_session_id",),
                        "session_end must match the active session ID.",
                    )
                )
            elif lifecycle_ready:
                self._active_session_id = None
                self._active_session_start_sequence = None
        elif kind is CaptureRecordKind.CAPTURE_END:
            self._capture_end_seen = True
            self._declared_complete = bool(envelope["complete"])
            if self._active_session_id is not None:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.CAPTURE_END_WITH_ACTIVE_SESSION,
                        locator,
                        ("kind",),
                        "capture_end cannot close an active collector session.",
                    )
                )
            if self._declared_complete is False:
                diagnostics.append(
                    _diagnostic(
                        CaptureDiagnosticCode.CAPTURE_DECLARED_INCOMPLETE,
                        locator,
                        ("complete",),
                        "The capture producer declared this capture incomplete.",
                    )
                )

        self._saw_structural_record = True
        return tuple(diagnostics)

    def _record_diagnostics(
        self, diagnostics: Sequence[CaptureDiagnostic]
    ) -> None:
        """Retain bounded file-level diagnostics and compromise state."""

        for diagnostic in diagnostics:
            if _is_compromising(diagnostic.code):
                self._structurally_compromised = True
            _append_bounded_capture_diagnostic(self._diagnostics, diagnostic)

    def _finalize(self) -> None:
        """Close, verify mutation state, and expose the immutable read summary."""

        final_diagnostics: list[CaptureDiagnostic] = []
        if not self._capture_started:
            final_diagnostics.append(
                _diagnostic(
                    CaptureDiagnosticCode.MISSING_CAPTURE_START,
                    "eof",
                    (),
                    "Capture ended without one valid capture_start record.",
                )
            )
        if not self._capture_end_seen:
            final_diagnostics.append(
                _diagnostic(
                    CaptureDiagnosticCode.MISSING_CAPTURE_END,
                    "eof",
                    (),
                    "Capture reached EOF without capture_end.",
                )
            )
        if self._active_session_id is not None:
            final_diagnostics.append(
                _diagnostic(
                    CaptureDiagnosticCode.SESSION_LEFT_OPEN,
                    "eof",
                    (),
                    "Capture reached EOF with an active collector session.",
                )
            )
        self._record_diagnostics(final_diagnostics)

        fingerprint = self._fingerprint
        if fingerprint is None:
            raise CaptureReaderStateError("capture reader was not initialized")
        if self._stream is not None:
            try:
                self._stream.close()
            except OSError:
                self._stream = None
                self._closed = True
                raise CaptureInputError(
                    "capture input could not be closed safely"
                ) from None
            self._stream = None
        self._closed = True
        try:
            verify_unchanged(fingerprint)
        except InputChangedError:
            raise InputChangedError(
                "INPUT_CHANGED: capture input changed during reading"
            ) from None
        except OSError:
            raise InputChangedError(
                "INPUT_CHANGED: capture input could not be verified after reading"
            ) from None
        complete = (
            self._capture_started
            and self._capture_end_seen
            and self._declared_complete is True
            and self._active_session_id is None
            and not self._structurally_compromised
        )
        self._summary = CaptureReadSummary(
            source_id=self._source_id,
            input_sha256=fingerprint.sha256,
            physical_record_count=self._line_number,
            accepted_record_count=self._accepted_record_count,
            declared_complete=self._declared_complete,
            structurally_compromised=self._structurally_compromised,
            verified_unchanged=True,
            complete=complete,
            diagnostics=tuple(self._diagnostics),
        )
def _validate_envelope(
    value: object, locator: str
) -> tuple[CaptureDiagnostic, ...]:
    """Check exact per-kind capture-envelope fields and scalar invariants."""

    if not isinstance(value, dict):
        return (
            _diagnostic(
                CaptureDiagnosticCode.ENVELOPE_VIOLATION,
                locator,
                (),
                "Each capture JSONL record must be one JSON object.",
            ),
        )

    diagnostics: list[CaptureDiagnostic] = []
    kind_value = value.get("kind")
    kind = (
        CaptureRecordKind(kind_value)
        if isinstance(kind_value, str)
        and kind_value in {item.value for item in CaptureRecordKind}
        else None
    )
    required = _COMMON_REQUIRED | (_KIND_REQUIRED[kind] if kind else frozenset())
    allowed = required | _COMMON_OPTIONAL
    for key in sorted(required - value.keys()):
        _append_bounded_capture_diagnostic(
            diagnostics,
            _envelope_failure(locator, key, "Capture record is missing a required field.")
        )
    for key in value:
        if key not in allowed:
            _append_bounded_capture_diagnostic(
                diagnostics,
                _envelope_failure(
                    locator,
                    key,
                    "Capture record contains a field not allowed for its kind.",
                ),
            )
        if len(diagnostics) > _MAX_CAPTURE_DIAGNOSTICS:
            break

    _require_exact_string(value, "schema", CAPTURE_SCHEMA_ID, locator, diagnostics)
    if kind is None and "kind" in value:
        _append_bounded_capture_diagnostic(
            diagnostics,
            _envelope_failure(
                locator,
                "kind",
                "Capture record kind is unsupported or incorrectly typed.",
            ),
        )
    _require_bounded_integer(value, "sequence", 0, _MAX_SIGNED_64, locator, diagnostics)
    _require_bounded_integer(
        value, "receive_time_ns", 0, _MAX_SIGNED_64, locator, diagnostics
    )
    if "receive_monotonic_ns" in value:
        _require_bounded_integer(
            value,
            "receive_monotonic_ns",
            0,
            _MAX_SIGNED_64,
            locator,
            diagnostics,
        )
    if "collector_session_id" in value:
        _require_string_length(
            value,
            "collector_session_id",
            1,
            MAX_CAPTURE_SESSION_ID_CHARACTERS,
            locator,
            diagnostics,
        )
    if "message_family" in value:
        family = value["message_family"]
        if not isinstance(family, str) or family not in {
            item.value for item in VdaMessageFamily
        }:
            _append_bounded_capture_diagnostic(
                diagnostics,
                _envelope_failure(
                    locator,
                    "message_family",
                    "Declared message family is unsupported or incorrectly typed.",
                ),
            )
    if "topic" in value:
        _require_string_length(
            value,
            "topic",
            1,
            MAX_CAPTURE_TOPIC_CHARACTERS,
            locator,
            diagnostics,
        )
    if "qos" in value:
        _require_bounded_integer(value, "qos", 0, 2, locator, diagnostics)
    for field in ("retained", "duplicate", "complete"):
        if field in value and not isinstance(value[field], bool):
            _append_bounded_capture_diagnostic(
                diagnostics,
                _envelope_failure(
                    locator,
                    field,
                    "Capture record field has an incorrect JSON type.",
                ),
            )
    if "payload_base64" in value:
        payload_text = value["payload_base64"]
        if not isinstance(payload_text, str) or len(payload_text) > _MAX_BASE64_CHARACTERS:
            _append_bounded_capture_diagnostic(
                diagnostics,
                _envelope_failure(
                    locator,
                    "payload_base64",
                    "Base64 payload field has an invalid type or length.",
                ),
            )
    if "drop_count" in value:
        _require_bounded_integer(
            value,
            "drop_count",
            1,
            _MAX_SIGNED_64,
            locator,
            diagnostics,
        )
    if "drop_reason" in value:
        _require_string_length(
            value,
            "drop_reason",
            1,
            MAX_CAPTURE_DROP_REASON_CHARACTERS,
            locator,
            diagnostics,
        )
    return _ordered_capture_diagnostics(diagnostics)


def _require_exact_string(
    value: Mapping[str, object],
    field: str,
    expected: str,
    locator: str,
    diagnostics: list[CaptureDiagnostic],
) -> None:
    """Append a fixed diagnostic when one exact string field is invalid."""

    if field in value and value[field] != expected:
        _append_bounded_capture_diagnostic(
            diagnostics,
            _envelope_failure(
                locator,
                field,
                "Capture record schema identity is unsupported or incorrectly typed.",
            ),
        )


def _require_bounded_integer(
    value: Mapping[str, object],
    field: str,
    minimum: int,
    maximum: int,
    locator: str,
    diagnostics: list[CaptureDiagnostic],
) -> None:
    """Append a fixed diagnostic when one bounded integer field is invalid."""

    if field not in value:
        return
    candidate = value[field]
    if (
        isinstance(candidate, bool)
        or not isinstance(candidate, int)
        or not minimum <= candidate <= maximum
    ):
        _append_bounded_capture_diagnostic(
            diagnostics,
            _envelope_failure(
                locator,
                field,
                "Capture record integer is outside its supported range.",
            ),
        )


def _require_string_length(
    value: Mapping[str, object],
    field: str,
    minimum: int,
    maximum: int,
    locator: str,
    diagnostics: list[CaptureDiagnostic],
) -> None:
    """Append a fixed diagnostic when one bounded string field is invalid."""

    candidate = value[field]
    if not isinstance(candidate, str) or not minimum <= len(candidate) <= maximum:
        _append_bounded_capture_diagnostic(
            diagnostics,
            _envelope_failure(
                locator,
                field,
                "Capture record string has an invalid type or length.",
            ),
        )


def _decode_payload_base64(
    value: str,
    locator: str,
    max_message_bytes: int,
) -> tuple[bytes | None, CaptureDiagnostic | None]:
    """Decode canonical ASCII Base64 without exposing its source text."""

    try:
        encoded = value.encode("ascii", errors="strict")
        decoded = base64.b64decode(encoded, validate=True)
        canonical = base64.b64encode(decoded)
    except MemoryError:
        return None, _diagnostic(
            CaptureDiagnosticCode.RESOURCE_LIMIT,
            locator,
            ("payload_base64",),
            "Base64 decoding exceeded a runtime resource limit.",
        )
    except (UnicodeEncodeError, binascii.Error, ValueError):
        return None, _diagnostic(
            CaptureDiagnosticCode.INVALID_BASE64,
            locator,
            ("payload_base64",),
            "Message payload is not canonical valid Base64.",
        )
    if canonical != encoded:
        return None, _diagnostic(
            CaptureDiagnosticCode.INVALID_BASE64,
            locator,
            ("payload_base64",),
            "Message payload is not canonical valid Base64.",
        )
    if len(decoded) > max_message_bytes:
        return None, _diagnostic(
            CaptureDiagnosticCode.PAYLOAD_TOO_LARGE,
            locator,
            ("payload_base64",),
            "Decoded message payload exceeds the configured byte limit.",
        )
    return decoded, None


def _remove_line_terminator(raw_line: bytes) -> bytes:
    """Remove one LF or CRLF terminator without altering JSON bytes otherwise."""

    if not raw_line.endswith(b"\n"):
        return raw_line
    line = raw_line[:-1]
    return line[:-1] if line.endswith(b"\r") else line


def _optional_int(value: object) -> int | None:
    """Return an already validated optional integer with precise typing."""

    return int(value) if value is not None else None


def _diagnostic(
    code: CaptureDiagnosticCode,
    locator: str,
    path: tuple[object, ...],
    explanation: str,
) -> CaptureDiagnostic:
    """Construct one bounded portable capture diagnostic."""

    return CaptureDiagnostic(
        code=code,
        locator=locator,
        instance_path=bounded_json_pointer(path),
        explanation=explanation,
    )


def _envelope_failure(
    locator: str, field: str, explanation: str
) -> CaptureDiagnostic:
    """Construct one fixed envelope diagnostic at a bounded field path."""

    return _diagnostic(
        CaptureDiagnosticCode.ENVELOPE_VIOLATION,
        locator,
        (field,),
        explanation,
    )


def _ordered_capture_diagnostics(
    diagnostics: Sequence[CaptureDiagnostic],
) -> tuple[CaptureDiagnostic, ...]:
    """Return same-record capture diagnostics in deterministic order."""

    return tuple(
        sorted(
            diagnostics,
            key=lambda item: (
                item.code is CaptureDiagnosticCode.DIAGNOSTICS_TRUNCATED,
                item.instance_path,
                item.code.value,
                item.explanation,
            ),
        )
    )


def _append_bounded_capture_diagnostic(
    diagnostics: list[CaptureDiagnostic],
    diagnostic: CaptureDiagnostic,
) -> None:
    """Append one capture diagnostic without exceeding the result bound."""

    if len(diagnostics) < _MAX_CAPTURE_DIAGNOSTICS:
        diagnostics.append(diagnostic)
    elif len(diagnostics) == _MAX_CAPTURE_DIAGNOSTICS:
        diagnostics.append(
            _diagnostic(
                CaptureDiagnosticCode.DIAGNOSTICS_TRUNCATED,
                diagnostic.locator,
                (),
                "Additional capture diagnostics were omitted.",
            )
        )


def _is_compromising(code: CaptureDiagnosticCode) -> bool:
    """Return whether one diagnostic invalidates structural completeness."""

    return code not in _NON_COMPROMISING_CODES
