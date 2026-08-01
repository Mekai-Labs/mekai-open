"""Normalize recorded Capture JSONL facts and run recorded analysis."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence

from .capture_jsonl import (
    CaptureControlRecord,
    CaptureDiagnostic,
    CaptureDropRecord,
    CaptureMessageRecord,
    CaptureReadItem,
    CaptureReadSummary,
    CaptureReader,
    CaptureRecordKind,
    CaptureSessionRecord,
    InvalidCaptureRecord,
)
from .contracts import FunctionResult
from .function_registry import get_function_executor
from .input_fingerprint import InputChangedError
from .observations import (
    CaptureBoundaryKind,
    CaptureBoundaryObservation,
    CaptureDiscontinuityObservation,
    CollectorDropObservation,
    CollectorSessionObservation,
    InputMutationObservation,
    MessageDiscontinuityObservation,
    NormalizedCaptureSummary,
    NormalizedVdaObservation,
    RecordedObservation,
    RobotIdentity,
    SessionBoundaryKind,
)
from .state_stream_health import STATE_STREAM_HEALTH_QUALIFIED_ID
from .vda_schemas import DEFAULT_MAX_MESSAGE_BYTES


def normalize_capture_item(item: CaptureReadItem) -> RecordedObservation:
    """Translate one CaptureReader item without retaining its raw payload bytes."""

    if isinstance(item, CaptureMessageRecord):
        return _normalize_message(item)
    if isinstance(item, InvalidCaptureRecord):
        return CaptureDiscontinuityObservation(
            source_id=item.source_id,
            locator=item.locator,
            observation_time_ns=None,
            record_kind=None,
            diagnostic_codes=tuple(
                diagnostic.code.value for diagnostic in item.diagnostics
            ),
        )
    if not item.capture_accepted:
        return CaptureDiscontinuityObservation(
            source_id=item.source_id,
            locator=item.locator,
            observation_time_ns=item.observation_time_ns,
            record_kind=item.kind.value,
            diagnostic_codes=_capture_codes(item.capture_diagnostics),
        )
    if isinstance(item, CaptureControlRecord):
        kind = (
            CaptureBoundaryKind.START
            if item.kind is CaptureRecordKind.CAPTURE_START
            else CaptureBoundaryKind.END
        )
        return CaptureBoundaryObservation(
            source_id=item.source_id,
            locator=item.locator,
            observation_time_ns=item.observation_time_ns,
            sequence=item.sequence,
            kind=kind,
            declared_complete=item.complete,
            capture_diagnostic_codes=_capture_codes(item.capture_diagnostics),
        )
    if isinstance(item, CaptureSessionRecord):
        epoch = item.collector_session_start_sequence
        if epoch is None:
            raise RuntimeError("accepted collector session is missing its epoch")
        kind = (
            SessionBoundaryKind.START
            if item.kind is CaptureRecordKind.SESSION_START
            else SessionBoundaryKind.END
        )
        return CollectorSessionObservation(
            source_id=item.source_id,
            locator=item.locator,
            observation_time_ns=item.observation_time_ns,
            sequence=item.sequence,
            kind=kind,
            producer_session_id=item.collector_session_id,
            continuity_epoch=epoch,
            capture_diagnostic_codes=_capture_codes(item.capture_diagnostics),
        )
    if isinstance(item, CaptureDropRecord):
        epoch = item.collector_session_start_sequence
        if epoch is None:
            raise RuntimeError("accepted collector drop is missing its epoch")
        return CollectorDropObservation(
            source_id=item.source_id,
            locator=item.locator,
            observation_time_ns=item.observation_time_ns,
            sequence=item.sequence,
            continuity_epoch=epoch,
            producer_session_id=item.collector_session_id,
            drop_count=item.drop_count,
            drop_reason=item.drop_reason,
            capture_diagnostic_codes=_capture_codes(item.capture_diagnostics),
        )
    raise TypeError(f"unsupported capture item: {type(item).__name__}")


def normalize_capture_summary(summary: CaptureReadSummary) -> NormalizedCaptureSummary:
    """Translate an exhausted CaptureReader summary into the neutral boundary."""

    return NormalizedCaptureSummary(
        source_id=summary.source_id,
        input_sha256=summary.input_sha256,
        physical_record_count=summary.physical_record_count,
        accepted_record_count=summary.accepted_record_count,
        declared_complete=summary.declared_complete,
        structurally_compromised=summary.structurally_compromised,
        verified_unchanged=summary.verified_unchanged,
        complete=summary.complete,
        diagnostic_codes=tuple(
            (diagnostic.code.value, diagnostic.locator)
            for diagnostic in summary.diagnostics
        ),
    )


def analyze_recorded_capture(
    path: str | os.PathLike[str],
    source_id: str,
    *,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> FunctionResult:
    """Stream one capture through the recorded source-health executor."""

    executor = get_function_executor(
        STATE_STREAM_HEALTH_QUALIFIED_ID,
        source_id=source_id,
    )
    try:
        with CaptureReader(
            path,
            source_id,
            max_message_bytes=max_message_bytes,
        ) as reader:
            for item in reader:
                executor.consume(normalize_capture_item(item))
            summary = normalize_capture_summary(reader.summary)
    except InputChangedError:
        executor.consume(InputMutationObservation(source_id))
        return executor.finish(None)
    return executor.finish(summary)


def _normalize_message(item: CaptureMessageRecord) -> RecordedObservation:
    """Translate one typed message while keeping invalidity separate."""

    validated = item.validated_message
    if not item.eligible_for_functions:
        return MessageDiscontinuityObservation(
            source_id=item.source_id,
            locator=item.locator,
            observation_time_ns=item.observation_time_ns,
            continuity_epoch=item.collector_session_start_sequence,
            message_family=item.message_family,
            topic=item.topic,
            payload_sha256=item.payload_sha256,
            capture_accepted=item.capture_accepted,
            vda_valid=validated is not None,
            capture_diagnostic_codes=_capture_codes(item.capture_diagnostics),
            vda_diagnostic_codes=tuple(
                diagnostic.code.value
                for diagnostic in item.validation_diagnostics
            ),
        )
    if validated is None:
        raise RuntimeError("eligible capture message has no validated payload")
    epoch = item.collector_session_start_sequence
    decoded = validated.decoded
    if epoch is None or not isinstance(decoded, Mapping):
        raise RuntimeError("validated capture message is internally inconsistent")
    if validated.raw_sha256 != item.payload_sha256:
        raise RuntimeError("validated and captured payload identities differ")
    payload = decoded
    return NormalizedVdaObservation(
        source_id=item.source_id,
        locator=item.locator,
        observation_time_ns=item.observation_time_ns,
        continuity_epoch=epoch,
        message_family=item.message_family,
        topic=item.topic,
        robot_identity=RobotIdentity(
            manufacturer=str(payload["manufacturer"]),
            serial_number=str(payload["serialNumber"]),
        ),
        header_id=int(payload["headerId"]),
        source_timestamp=str(payload["timestamp"]),
        retained=item.retained,
        producer_duplicate=item.duplicate,
        payload_sha256=item.payload_sha256,
        validated_payload=payload,
        capture_diagnostic_codes=_capture_codes(item.capture_diagnostics),
    )


def _capture_codes(
    diagnostics: Sequence[CaptureDiagnostic],
) -> tuple[str, ...]:
    """Return symbolic capture codes from typed diagnostic objects."""

    return tuple(diagnostic.code.value for diagnostic in diagnostics)
