"""Calculate bounded recorded VDA state-stream health from neutral facts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .bounded_intervals import BoundedIntervalAccumulator
from .contracts import (
    Coverage,
    EvaluationWindow,
    FunctionResult,
    InputReference,
    MissingInterval,
    ResultBasis,
    ResultScope,
    ResultStatus,
    ScopeKind,
)
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
from .recorded_functions import MAX_VDA_HEADER_ID, STATE_CARRY_FORWARD_NS
from .source_ids import validate_source_id
from .vda_schemas import VdaMessageFamily

STATE_STREAM_HEALTH_FUNCTION_ID = "vda.state_stream_health"
STATE_STREAM_HEALTH_VERSION = "0.1.0"
STATE_STREAM_HEALTH_QUALIFIED_ID = (
    f"{STATE_STREAM_HEALTH_FUNCTION_ID}@{STATE_STREAM_HEALTH_VERSION}"
)
MAX_STATE_STREAMS = 1_024
MAX_CONNECTION_IDENTITIES = 1_024
MAX_SOURCE_HEALTH_DIAGNOSTICS = 256
MAX_SOURCE_HEALTH_SUMMARY_DIAGNOSTICS = 8
MAX_SOURCE_HEALTH_TERMINAL_DIAGNOSTICS = 2
MAX_SOURCE_HEALTH_INPUT_REFERENCES = 256
MAX_SOURCE_HEALTH_INTERVALS_PER_STREAM = 256
MAX_SOURCE_HEALTH_COVERAGE_INTERVALS = 256
MAX_SOURCE_HEALTH_IDENTITY_CHARACTERS = 4_096


class SourceHealthDiagnosticCode(StrEnum):
    """Classify deterministic source-health completeness diagnostics."""

    WINDOW_UNDEFINED = "WINDOW_UNDEFINED"
    INPUT_CHANGED = "INPUT_CHANGED"
    CAPTURE_INCOMPLETE = "CAPTURE_INCOMPLETE"
    CAPTURE_STRUCTURALLY_COMPROMISED = "CAPTURE_STRUCTURALLY_COMPROMISED"
    CAPTURE_RECORD_INVALID = "CAPTURE_RECORD_INVALID"
    CAPTURE_MESSAGE_REJECTED = "CAPTURE_MESSAGE_REJECTED"
    VDA_MESSAGE_INVALID = "VDA_MESSAGE_INVALID"
    UTC_TIME_REGRESSION = "UTC_TIME_REGRESSION"
    COLLECTOR_SESSION_GAP = "COLLECTOR_SESSION_GAP"
    COLLECTOR_DROP = "COLLECTOR_DROP"
    RETAINED_STATE_IGNORED = "RETAINED_STATE_IGNORED"
    HEADER_OUT_OF_RANGE = "HEADER_OUT_OF_RANGE"
    HEADER_GAP = "HEADER_GAP"
    HEADER_REGRESSION = "HEADER_REGRESSION"
    HEADER_CONFLICT = "HEADER_CONFLICT"
    UNCONFIRMED_STATE_SILENCE = "UNCONFIRMED_STATE_SILENCE"
    COVERAGE_INTERVAL_DETAILS_TRUNCATED = (
        "COVERAGE_INTERVAL_DETAILS_TRUNCATED"
    )
    COVERAGE_DURATION_UNAVAILABLE = "COVERAGE_DURATION_UNAVAILABLE"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    DIAGNOSTICS_TRUNCATED = "DIAGNOSTICS_TRUNCATED"


@dataclass(frozen=True, slots=True)
class _StateStreamKey:
    """Identify one independently sequenced state stream."""

    source_id: str
    continuity_epoch: int
    topic: str | None
    manufacturer: str
    serial_number: str
    message_family: str


@dataclass(frozen=True, slots=True, order=True)
class _ConnectionKey:
    """Identify connection state shared by one robot within one epoch."""

    continuity_epoch: int
    manufacturer: str
    serial_number: str


@dataclass(frozen=True, slots=True)
class _HealthInterval:
    """Hold one non-empty half-open health interval."""

    start_ns: int
    end_ns: int

    def to_dict(self) -> dict[str, int]:
        """Return the JSON-compatible interval representation."""

        return {"start_ns": self.start_ns, "end_ns": self.end_ns}


@dataclass(frozen=True, slots=True)
class _ReferenceCandidate:
    """Retain bounded message identity until the input digest is available."""

    locator: str
    message_family: str
    topic: str | None
    header_identity: str | None


@dataclass(slots=True)
class _StateStreamState:
    """Retain constant-size sequencing state and bounded interval lists."""

    key: _StateStreamKey
    robot_identity: RobotIdentity
    first_observation_time_ns: int
    last_observation_time_ns: int
    usable_state_message_count: int = 0
    retained_state_count: int = 0
    producer_duplicate_flag_count: int = 0
    exact_retransmission_count: int = 0
    header_gap_event_count: int = 0
    missing_header_id_count: int = 0
    header_regression_count: int = 0
    header_conflict_count: int = 0
    observed_inter_arrival_count: int = 0
    minimum_inter_arrival_ns: int | None = None
    maximum_inter_arrival_ns: int | None = None
    last_header_id: int | None = None
    last_payload_sha256: str | None = None
    last_transition_time_ns: int | None = None
    silence_baseline_time_ns: int | None = None
    silence_cursor_ns: int | None = None
    hibernation_start_ns: int | None = None
    unconfirmed_silence: list[_HealthInterval] = field(default_factory=list)
    confirmed_hibernation_silence: list[_HealthInterval] = field(
        default_factory=list
    )


class StateStreamHealthExecutor:
    """Accumulate one source-scoped result in a single bounded-memory pass."""

    def __init__(self, source_id: str) -> None:
        """Initialize empty counters and bounded state for one source."""

        validate_source_id(source_id)
        self._source_id = source_id
        self._finished = False
        self._input_changed = False
        self._capture_start_ns: int | None = None
        self._capture_end_ns: int | None = None
        self._active_epoch: int | None = None
        self._gap_start_ns: int | None = None
        self._coverage_gaps: BoundedIntervalAccumulator | None = None
        self._streams: dict[_StateStreamKey, _StateStreamState] = {}
        self._connection_states: dict[_ConnectionKey, str] = {}
        self._message_counts = {
            family.value: 0 for family in VdaMessageFamily
        }
        self._total_typed_messages = 0
        self._eligible_messages = 0
        self._capture_rejected_messages = 0
        self._vda_invalid_messages = 0
        self._accepted_session_epochs = 0
        self._session_boundaries = 0
        self._drop_records = 0
        self._dropped_messages = 0
        self._partial = False
        self._diagnostics: list[str] = []
        self._diagnostic_seen: set[str] = set()
        self._diagnostics_truncated = False
        self._summary_diagnostics: list[str] = []
        self._summary_diagnostic_seen: set[str] = set()
        self._terminal_diagnostics: list[str] = []
        self._terminal_diagnostic_seen: set[str] = set()
        self._reference_candidates: list[_ReferenceCandidate] = []

    def consume(self, observation: RecordedObservation) -> None:
        """Consume one normalized fact in its original input order."""

        if self._finished:
            raise RuntimeError("source-health executor is already finished")
        if observation.source_id != self._source_id:
            raise ValueError("observation source does not match executor source")
        if isinstance(observation, InputMutationObservation):
            self._input_changed = True
            self._append_terminal_diagnostic(
                SourceHealthDiagnosticCode.INPUT_CHANGED
            )
            return
        if isinstance(observation, CaptureBoundaryObservation):
            self._record_capture_codes(
                observation.capture_diagnostic_codes, observation.locator
            )
            self._consume_capture_boundary(observation)
            return
        if isinstance(observation, CollectorSessionObservation):
            self._record_capture_codes(
                observation.capture_diagnostic_codes, observation.locator
            )
            self._consume_session_boundary(observation)
            return
        if isinstance(observation, CollectorDropObservation):
            self._record_capture_codes(
                observation.capture_diagnostic_codes, observation.locator
            )
            self._drop_records += 1
            self._dropped_messages += observation.drop_count
            self._append_diagnostic(
                SourceHealthDiagnosticCode.COLLECTOR_DROP,
                observation.locator,
            )
            return
        if isinstance(observation, NormalizedVdaObservation):
            self._record_capture_codes(
                observation.capture_diagnostic_codes, observation.locator
            )
            self._consume_valid_message(observation)
            return
        if isinstance(observation, MessageDiscontinuityObservation):
            self._consume_message_discontinuity(observation)
            return
        if isinstance(observation, CaptureDiscontinuityObservation):
            self._append_diagnostic(
                SourceHealthDiagnosticCode.CAPTURE_RECORD_INVALID,
                observation.locator,
            )
            if "UTC_TIME_REGRESSION" in observation.diagnostic_codes:
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.UTC_TIME_REGRESSION,
                    observation.locator,
                )
            return
        raise TypeError(f"unsupported recorded observation: {type(observation).__name__}")

    def finish(
        self, summary: NormalizedCaptureSummary | None
    ) -> FunctionResult:
        """Finalize one deterministic result after capture exhaustion or mutation."""

        if self._finished:
            raise RuntimeError("source-health executor is already finished")
        self._finished = True
        if summary is not None and summary.source_id != self._source_id:
            raise ValueError("capture summary source does not match executor source")
        if summary is not None:
            self._record_summary_state(summary)
        if self._input_changed or summary is None or not summary.verified_unchanged:
            self._append_terminal_diagnostic(
                SourceHealthDiagnosticCode.INPUT_CHANGED
            )
            return self._not_computable(summary)
        if (
            self._capture_start_ns is None
            or self._capture_end_ns is None
            or self._capture_end_ns <= self._capture_start_ns
        ):
            self._append_terminal_diagnostic(
                SourceHealthDiagnosticCode.WINDOW_UNDEFINED
            )
            return self._not_computable(summary)

        window = EvaluationWindow(self._capture_start_ns, self._capture_end_ns)
        gaps = self._coverage_missing_intervals(window)
        observed_duration = self._coverage_observed_duration(window, gaps)
        coverage = Coverage(
            eligible_duration_ns=window.duration_ns,
            observed_duration_ns=observed_duration,
            missing_intervals=tuple(gaps),
            known_missing_interval_count=(
                self._coverage_gaps.known_interval_count
                if self._coverage_gaps is not None
                else 0
            ),
            missing_interval_details_truncated=(
                self._coverage_gaps.details_truncated
                if self._coverage_gaps is not None
                else False
            ),
        )
        value = self._result_value(summary, window)
        status = ResultStatus.PARTIAL if self._partial else ResultStatus.COMPUTED
        return FunctionResult(
            function_id=STATE_STREAM_HEALTH_FUNCTION_ID,
            function_version=STATE_STREAM_HEALTH_VERSION,
            status=status,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.SOURCE, (self._source_id,)),
            window=window,
            coverage=coverage,
            method_version=STATE_STREAM_HEALTH_VERSION,
            value=value,
            unit=None,
            numerator=None,
            denominator=None,
            input_references=self._input_references(summary.input_sha256),
            diagnostics=self._diagnostic_values(),
        )

    def _consume_capture_boundary(
        self, observation: CaptureBoundaryObservation
    ) -> None:
        """Record an accepted capture boundary and known outside-session time."""

        if observation.kind is CaptureBoundaryKind.START:
            self._capture_start_ns = observation.observation_time_ns
            self._gap_start_ns = observation.observation_time_ns
            return
        if self._active_epoch is not None:
            self._close_epoch(
                self._active_epoch,
                observation.observation_time_ns,
                observation.locator,
            )
            self._active_epoch = None
        self._capture_end_ns = observation.observation_time_ns
        if self._gap_start_ns is not None:
            self._append_coverage_gap(
                self._gap_start_ns,
                observation.observation_time_ns,
                observation.locator,
            )
            self._gap_start_ns = None
        if observation.declared_complete is not True:
            self._append_diagnostic(
                SourceHealthDiagnosticCode.CAPTURE_INCOMPLETE,
                observation.locator,
            )

    def _consume_session_boundary(
        self, observation: CollectorSessionObservation
    ) -> None:
        """Track accepted session epochs and close continuity-dependent state."""

        self._session_boundaries += 1
        if observation.kind is SessionBoundaryKind.START:
            self._accepted_session_epochs += 1
            if self._gap_start_ns is not None:
                self._append_coverage_gap(
                    self._gap_start_ns,
                    observation.observation_time_ns,
                    observation.locator,
                )
            self._gap_start_ns = None
            self._active_epoch = observation.continuity_epoch
            return
        self._close_epoch(
            observation.continuity_epoch,
            observation.observation_time_ns,
            observation.locator,
        )
        self._active_epoch = None
        self._gap_start_ns = observation.observation_time_ns

    def _consume_valid_message(
        self, observation: NormalizedVdaObservation
    ) -> None:
        """Count one eligible message and route relevant families."""

        self._total_typed_messages += 1
        self._eligible_messages += 1
        self._message_counts[observation.message_family.value] += 1
        self._append_reference(
            observation.locator,
            observation.message_family.value,
            observation.topic,
            f"headerId:{observation.header_id}",
        )
        if observation.message_family is VdaMessageFamily.CONNECTION:
            self._consume_connection(observation)
        elif observation.message_family is VdaMessageFamily.STATE:
            self._consume_state(observation)

    def _consume_message_discontinuity(
        self, observation: MessageDiscontinuityObservation
    ) -> None:
        """Count one excluded typed message without creating transitions."""

        self._total_typed_messages += 1
        self._message_counts[observation.message_family.value] += 1
        self._append_reference(
            observation.locator,
            observation.message_family.value,
            observation.topic,
            None,
        )
        if not observation.capture_accepted:
            self._capture_rejected_messages += 1
            self._append_diagnostic(
                SourceHealthDiagnosticCode.CAPTURE_MESSAGE_REJECTED,
                observation.locator,
            )
        if not observation.vda_valid:
            self._vda_invalid_messages += 1
            self._append_diagnostic(
                SourceHealthDiagnosticCode.VDA_MESSAGE_INVALID,
                observation.locator,
            )
        self._record_capture_codes(
            observation.capture_diagnostic_codes, observation.locator
        )

    def _consume_connection(self, observation: NormalizedVdaObservation) -> None:
        """Apply one uint32-header connection state from capture receipt time."""

        if not 0 <= observation.header_id <= MAX_VDA_HEADER_ID:
            self._append_diagnostic(
                SourceHealthDiagnosticCode.HEADER_OUT_OF_RANGE,
                observation.locator,
            )
            return
        if not self._identity_within_limit(observation, observation.locator):
            return
        key = _ConnectionKey(
            observation.continuity_epoch,
            observation.robot_identity.manufacturer,
            observation.robot_identity.serial_number,
        )
        if key not in self._connection_states and (
            len(self._connection_states) >= MAX_CONNECTION_IDENTITIES
        ):
            self._append_diagnostic(
                SourceHealthDiagnosticCode.RESOURCE_LIMIT,
                observation.locator,
            )
            return
        previous = self._connection_states.get(key)
        current = str(observation.validated_payload["connectionState"])
        matching = tuple(self._matching_streams(key))
        for stream in matching:
            self._advance_silence(
                stream,
                observation.observation_time_ns,
                previous,
                observation.locator,
            )
            if previous == "HIBERNATING" and current != "HIBERNATING":
                self._close_hibernation(
                    stream,
                    observation.observation_time_ns,
                    observation.locator,
                )
            elif previous != "HIBERNATING" and current == "HIBERNATING":
                stream.hibernation_start_ns = observation.observation_time_ns
        self._connection_states[key] = current

    def _consume_state(self, observation: NormalizedVdaObservation) -> None:
        """Update one independent state stream under deterministic header rules."""

        if not self._identity_within_limit(observation, observation.locator):
            return
        key = _StateStreamKey(
            source_id=observation.source_id,
            continuity_epoch=observation.continuity_epoch,
            topic=observation.topic,
            manufacturer=observation.robot_identity.manufacturer,
            serial_number=observation.robot_identity.serial_number,
            message_family=observation.message_family.value,
        )
        stream = self._streams.get(key)
        if stream is None:
            if len(self._streams) >= MAX_STATE_STREAMS:
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.RESOURCE_LIMIT,
                    observation.locator,
                )
                return
            stream = _StateStreamState(
                key=key,
                robot_identity=observation.robot_identity,
                first_observation_time_ns=observation.observation_time_ns,
                last_observation_time_ns=observation.observation_time_ns,
            )
            connection = self._connection_states.get(
                _ConnectionKey(
                    observation.continuity_epoch,
                    observation.robot_identity.manufacturer,
                    observation.robot_identity.serial_number,
                )
            )
            if connection == "HIBERNATING":
                stream.hibernation_start_ns = observation.observation_time_ns
            self._streams[key] = stream
        else:
            stream.last_observation_time_ns = observation.observation_time_ns

        connection_state = self._connection_states.get(
            _ConnectionKey(
                observation.continuity_epoch,
                observation.robot_identity.manufacturer,
                observation.robot_identity.serial_number,
            )
        )
        self._advance_silence(
            stream,
            observation.observation_time_ns,
            connection_state,
            observation.locator,
        )
        if observation.producer_duplicate is True:
            stream.producer_duplicate_flag_count += 1
        if observation.retained is True:
            stream.retained_state_count += 1
            self._append_diagnostic(
                SourceHealthDiagnosticCode.RETAINED_STATE_IGNORED,
                observation.locator,
                partial=False,
            )
        if not 0 <= observation.header_id <= MAX_VDA_HEADER_ID:
            self._append_diagnostic(
                SourceHealthDiagnosticCode.HEADER_OUT_OF_RANGE,
                observation.locator,
            )
            return
        if observation.retained is True:
            return

        stream.usable_state_message_count += 1
        previous_header = stream.last_header_id
        if previous_header is None:
            self._advance_header_baseline(stream, observation)
            return
        if observation.header_id == previous_header:
            if observation.payload_sha256 == stream.last_payload_sha256:
                stream.exact_retransmission_count += 1
            else:
                stream.header_conflict_count += 1
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.HEADER_CONFLICT,
                    observation.locator,
                )
            return
        if observation.header_id < previous_header:
            stream.header_regression_count += 1
            self._append_diagnostic(
                SourceHealthDiagnosticCode.HEADER_REGRESSION,
                observation.locator,
            )
            return
        if observation.header_id > previous_header + 1:
            stream.header_gap_event_count += 1
            stream.missing_header_id_count += (
                observation.header_id - previous_header - 1
            )
            self._append_diagnostic(
                SourceHealthDiagnosticCode.HEADER_GAP,
                observation.locator,
            )
        self._advance_header_baseline(stream, observation)

    def _advance_header_baseline(
        self,
        stream: _StateStreamState,
        observation: NormalizedVdaObservation,
    ) -> None:
        """Accept a normal or gapped header and update safe cadence state."""

        previous_time = stream.last_transition_time_ns
        if previous_time is not None:
            if observation.observation_time_ns >= previous_time:
                duration = observation.observation_time_ns - previous_time
                stream.observed_inter_arrival_count += 1
                stream.minimum_inter_arrival_ns = (
                    duration
                    if stream.minimum_inter_arrival_ns is None
                    else min(stream.minimum_inter_arrival_ns, duration)
                )
                stream.maximum_inter_arrival_ns = (
                    duration
                    if stream.maximum_inter_arrival_ns is None
                    else max(stream.maximum_inter_arrival_ns, duration)
                )
            else:
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.UTC_TIME_REGRESSION,
                    observation.locator,
                )
        stream.last_header_id = observation.header_id
        stream.last_payload_sha256 = observation.payload_sha256
        stream.last_transition_time_ns = observation.observation_time_ns
        if (
            stream.silence_baseline_time_ns is None
            or observation.observation_time_ns
            >= stream.silence_baseline_time_ns
        ):
            stream.silence_baseline_time_ns = observation.observation_time_ns
            stream.silence_cursor_ns = observation.observation_time_ns

    def _advance_silence(
        self,
        stream: _StateStreamState,
        end_ns: int,
        connection_state: str | None,
        locator: str,
    ) -> None:
        """Advance missing-silence accounting without changing message order."""

        baseline = stream.silence_baseline_time_ns
        cursor = stream.silence_cursor_ns
        if baseline is None or cursor is None or end_ns <= cursor:
            return
        start_ns = max(cursor, baseline + STATE_CARRY_FORWARD_NS)
        if end_ns > start_ns and connection_state != "HIBERNATING":
            if self._append_stream_interval(
                stream.unconfirmed_silence,
                start_ns,
                end_ns,
                locator,
            ):
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.UNCONFIRMED_STATE_SILENCE,
                    locator,
                )
        stream.silence_cursor_ns = end_ns

    def _close_hibernation(
        self,
        stream: _StateStreamState,
        end_ns: int,
        locator: str,
    ) -> None:
        """Close one confirmed hibernation-silence interval at a boundary."""

        start_ns = stream.hibernation_start_ns
        if start_ns is not None:
            self._append_stream_interval(
                stream.confirmed_hibernation_silence,
                start_ns,
                end_ns,
                locator,
            )
        stream.hibernation_start_ns = None

    def _close_epoch(self, epoch: int, end_ns: int, locator: str) -> None:
        """End all state and connection continuity for one collector epoch."""

        for stream in self._streams.values():
            if stream.key.continuity_epoch != epoch:
                continue
            connection_key = _ConnectionKey(
                epoch,
                stream.key.manufacturer,
                stream.key.serial_number,
            )
            connection = self._connection_states.get(connection_key)
            self._advance_silence(stream, end_ns, connection, locator)
            self._close_hibernation(stream, end_ns, locator)
        expired = [
            key
            for key in self._connection_states
            if key.continuity_epoch == epoch
        ]
        for key in expired:
            del self._connection_states[key]

    def _matching_streams(
        self, connection_key: _ConnectionKey
    ) -> tuple[_StateStreamState, ...]:
        """Return bounded streams sharing one exact robot identity and epoch."""

        return tuple(
            stream
            for stream in self._streams.values()
            if stream.key.continuity_epoch == connection_key.continuity_epoch
            and stream.key.manufacturer == connection_key.manufacturer
            and stream.key.serial_number == connection_key.serial_number
        )

    def _identity_within_limit(
        self, observation: NormalizedVdaObservation, locator: str
    ) -> bool:
        """Reject oversized retained stream identities without truncating them."""

        identity = observation.robot_identity
        if (
            len(identity.manufacturer) <= MAX_SOURCE_HEALTH_IDENTITY_CHARACTERS
            and len(identity.serial_number)
            <= MAX_SOURCE_HEALTH_IDENTITY_CHARACTERS
        ):
            return True
        self._append_diagnostic(
            SourceHealthDiagnosticCode.RESOURCE_LIMIT,
            locator,
        )
        return False

    def _append_stream_interval(
        self,
        intervals: list[_HealthInterval],
        start_ns: int,
        end_ns: int,
        locator: str,
    ) -> bool:
        """Merge one interval or diagnose per-stream interval truncation."""

        if end_ns <= start_ns:
            return False
        if intervals and start_ns <= intervals[-1].end_ns:
            previous = intervals[-1]
            intervals[-1] = _HealthInterval(
                min(previous.start_ns, start_ns),
                max(previous.end_ns, end_ns),
            )
            return True
        if len(intervals) >= MAX_SOURCE_HEALTH_INTERVALS_PER_STREAM:
            self._append_diagnostic(
                SourceHealthDiagnosticCode.RESOURCE_LIMIT,
                locator,
            )
            return False
        intervals.append(_HealthInterval(start_ns, end_ns))
        return True

    def _append_coverage_gap(
        self, start_ns: int, end_ns: int, locator: str
    ) -> None:
        """Accumulate every known gap while retaining bounded interval detail."""

        if end_ns <= start_ns:
            return
        if self._coverage_gaps is None:
            self._coverage_gaps = BoundedIntervalAccumulator(
                MAX_SOURCE_HEALTH_COVERAGE_INTERVALS
            )
        first_truncation = self._coverage_gaps.add(
            start_ns,
            end_ns,
            "COLLECTOR_SESSION_GAP",
        )
        if first_truncation:
            self._append_summary_diagnostic(
                SourceHealthDiagnosticCode.COVERAGE_INTERVAL_DETAILS_TRUNCATED
            )
        self._append_diagnostic(
            SourceHealthDiagnosticCode.COLLECTOR_SESSION_GAP,
            locator,
        )

    def _coverage_observed_duration(
        self,
        window: EvaluationWindow,
        retained_gaps: list[MissingInterval],
    ) -> int | None:
        """Return exact observed time or explicitly withhold unsupported arithmetic."""

        del retained_gaps
        if self._coverage_gaps is None:
            return window.duration_ns
        missing_duration = self._coverage_gaps.exact_union_duration_ns(window)
        if missing_duration is not None:
            return window.duration_ns - missing_duration
        self._append_summary_diagnostic(
            SourceHealthDiagnosticCode.COVERAGE_DURATION_UNAVAILABLE
        )
        return None

    def _coverage_missing_intervals(
        self, window: EvaluationWindow
    ) -> list[MissingInterval]:
        """Clip, sort, and merge retained known session gaps."""

        if self._coverage_gaps is None:
            return []
        return [
            MissingInterval(item.start_ns, item.end_ns, item.reason)
            for item in self._coverage_gaps.retained_intervals(window)
        ]

    def _append_reference(
        self,
        locator: str,
        message_family: str,
        topic: str | None,
        header_identity: str | None,
    ) -> None:
        """Retain one bounded input-reference candidate."""

        if len(self._reference_candidates) >= MAX_SOURCE_HEALTH_INPUT_REFERENCES:
            self._append_diagnostic(
                SourceHealthDiagnosticCode.RESOURCE_LIMIT,
                locator,
            )
            return
        self._reference_candidates.append(
            _ReferenceCandidate(
                locator=locator,
                message_family=message_family,
                topic=topic,
                header_identity=header_identity,
            )
        )

    def _input_references(self, input_sha256: str) -> tuple[InputReference, ...]:
        """Bind retained message candidates to the verified capture digest."""

        return tuple(
            InputReference(
                source_id=self._source_id,
                input_sha256=input_sha256,
                locator=item.locator,
                message_family=item.message_family,
                topic=item.topic,
                header_identity=item.header_identity,
            )
            for item in self._reference_candidates
        )

    def _record_capture_codes(self, codes: tuple[str, ...], locator: str) -> None:
        """Map capture timing/completeness facts into health diagnostics."""

        for code in codes:
            if code == "UTC_TIME_REGRESSION":
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.UTC_TIME_REGRESSION,
                    locator,
                )
            elif code == "CAPTURE_DECLARED_INCOMPLETE":
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.CAPTURE_INCOMPLETE,
                    locator,
                )
            else:
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.CAPTURE_STRUCTURALLY_COMPROMISED,
                    locator,
                )

    def _record_summary_state(self, summary: NormalizedCaptureSummary) -> None:
        """Apply verified file-level completion facts before result creation."""

        if summary.structurally_compromised:
            self._append_summary_diagnostic(
                SourceHealthDiagnosticCode.CAPTURE_STRUCTURALLY_COMPROMISED
            )
        if not summary.complete:
            self._append_summary_diagnostic(
                SourceHealthDiagnosticCode.CAPTURE_INCOMPLETE
            )
        for code, locator in summary.diagnostic_codes:
            if code == "UTC_TIME_REGRESSION":
                self._append_diagnostic(
                    SourceHealthDiagnosticCode.UTC_TIME_REGRESSION,
                    locator,
                )

    def _append_diagnostic(
        self,
        code: SourceHealthDiagnosticCode,
        locator: str | None = None,
        *,
        partial: bool = True,
    ) -> None:
        """Append one unique bounded event diagnostic and track completeness."""

        if partial:
            self._partial = True
        rendered = code.value if locator is None else f"{code.value}@{locator}"
        if rendered in self._diagnostic_seen:
            return
        if len(self._diagnostics) < MAX_SOURCE_HEALTH_DIAGNOSTICS:
            self._diagnostics.append(rendered)
            self._diagnostic_seen.add(rendered)
            return
        self._diagnostics_truncated = True
        self._partial = True

    def _append_summary_diagnostic(
        self, code: SourceHealthDiagnosticCode
    ) -> None:
        """Retain a bounded source-summary diagnostic outside the event budget."""

        self._partial = True
        rendered = code.value
        if rendered in self._summary_diagnostic_seen:
            return
        if len(self._summary_diagnostics) >= MAX_SOURCE_HEALTH_SUMMARY_DIAGNOSTICS:
            raise RuntimeError("source-health summary diagnostic bound is inconsistent")
        self._summary_diagnostics.append(rendered)
        self._summary_diagnostic_seen.add(rendered)

    def _append_terminal_diagnostic(
        self, code: SourceHealthDiagnosticCode
    ) -> None:
        """Retain a terminal non-computability reason outside event detail."""

        if code not in {
            SourceHealthDiagnosticCode.INPUT_CHANGED,
            SourceHealthDiagnosticCode.WINDOW_UNDEFINED,
        }:
            raise ValueError("diagnostic code is not a terminal reason")
        rendered = code.value
        if rendered in self._terminal_diagnostic_seen:
            return
        if len(self._terminal_diagnostics) >= MAX_SOURCE_HEALTH_TERMINAL_DIAGNOSTICS:
            raise RuntimeError("source-health terminal diagnostic bound is inconsistent")
        self._terminal_diagnostics.append(rendered)
        self._terminal_diagnostic_seen.add(rendered)

    def _diagnostic_values(self) -> tuple[str, ...]:
        """Return bounded event, summary, and terminal diagnostics in stable order."""

        values = list(self._diagnostics)
        if self._diagnostics_truncated:
            values.append(SourceHealthDiagnosticCode.DIAGNOSTICS_TRUNCATED.value)
        values.extend(self._summary_diagnostics)
        values.extend(self._terminal_diagnostics)
        return tuple(values)

    def _result_value(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
    ) -> dict[str, object]:
        """Build the bounded structured source and stream-health value."""

        streams = [
            self._stream_value(stream, window)
            for stream in sorted(
                self._streams.values(),
                key=lambda item: (
                    item.key.manufacturer,
                    item.key.serial_number,
                    item.key.topic or "",
                    item.key.continuity_epoch,
                    item.key.message_family,
                    item.key.source_id,
                ),
            )
        ]
        return {
            "source_id": self._source_id,
            "capture": {
                "physical_record_count": summary.physical_record_count,
                "capture_accepted_record_count": summary.accepted_record_count,
                "declared_complete": summary.declared_complete,
                "structurally_complete": not summary.structurally_compromised,
                "mutation_verified": summary.verified_unchanged,
            },
            "messages": {
                "total_typed_message_records": self._total_typed_messages,
                "function_eligible_message_count": self._eligible_messages,
                "capture_rejected_typed_message_count": (
                    self._capture_rejected_messages
                ),
                "vda_invalid_message_count": self._vda_invalid_messages,
                "counts_by_message_family": dict(self._message_counts),
            },
            "sessions_and_drops": {
                "accepted_collector_session_epoch_count": (
                    self._accepted_session_epochs
                ),
                "session_boundary_count": self._session_boundaries,
                "drop_record_count": self._drop_records,
                "dropped_message_count": self._dropped_messages,
            },
            "state_streams": streams,
        }

    def _stream_value(
        self, stream: _StateStreamState, window: EvaluationWindow
    ) -> dict[str, object]:
        """Build one deterministic stream row with clipped intervals."""

        return {
            "robot_identity": stream.robot_identity.to_dict(),
            "topic": stream.key.topic,
            "continuity_epoch": stream.key.continuity_epoch,
            "message_family": stream.key.message_family,
            "first_observation_time_ns": stream.first_observation_time_ns,
            "last_observation_time_ns": stream.last_observation_time_ns,
            "usable_state_message_count": stream.usable_state_message_count,
            "retained_state_count": stream.retained_state_count,
            "producer_duplicate_flag_count": (
                stream.producer_duplicate_flag_count
            ),
            "exact_retransmission_count": stream.exact_retransmission_count,
            "header_gap_event_count": stream.header_gap_event_count,
            "missing_header_id_count": stream.missing_header_id_count,
            "header_regression_count": stream.header_regression_count,
            "same_header_different_payload_conflict_count": (
                stream.header_conflict_count
            ),
            "observed_inter_arrival_count": stream.observed_inter_arrival_count,
            "minimum_observed_inter_arrival_ns": (
                stream.minimum_inter_arrival_ns
            ),
            "maximum_observed_inter_arrival_ns": (
                stream.maximum_inter_arrival_ns
            ),
            "unconfirmed_state_silence_intervals": [
                item.to_dict()
                for item in _clip_intervals(stream.unconfirmed_silence, window)
            ],
            "confirmed_hibernation_silence_intervals": [
                item.to_dict()
                for item in _clip_intervals(
                    stream.confirmed_hibernation_silence, window
                )
            ],
        }

    def _not_computable(
        self, summary: NormalizedCaptureSummary | None
    ) -> FunctionResult:
        """Return a source-scoped absence without inventing a window."""

        references = (
            self._input_references(summary.input_sha256)
            if (
                not self._input_changed
                and summary is not None
                and summary.verified_unchanged
            )
            else ()
        )
        return FunctionResult(
            function_id=STATE_STREAM_HEALTH_FUNCTION_ID,
            function_version=STATE_STREAM_HEALTH_VERSION,
            status=ResultStatus.NOT_COMPUTABLE,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.SOURCE, (self._source_id,)),
            window=None,
            coverage=Coverage(0, 0),
            method_version=STATE_STREAM_HEALTH_VERSION,
            value=None,
            unit=None,
            numerator=None,
            denominator=None,
            input_references=references,
            diagnostics=self._diagnostic_values(),
        )


def _clip_intervals(
    intervals: list[_HealthInterval], window: EvaluationWindow
) -> tuple[_HealthInterval, ...]:
    """Clip retained intervals to one evaluation window without reordering input."""

    return tuple(
        _HealthInterval(
            max(window.start_ns, interval.start_ns),
            min(window.end_ns, interval.end_ns),
        )
        for interval in intervals
        if min(window.end_ns, interval.end_ns)
        > max(window.start_ns, interval.start_ns)
    )
