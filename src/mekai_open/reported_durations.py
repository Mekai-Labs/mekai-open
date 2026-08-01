"""Calculate bounded robot-scoped reported durations from recorded facts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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
    RobotTarget,
    SessionBoundaryKind,
)
from .recorded_functions import MAX_VDA_HEADER_ID, STATE_CARRY_FORWARD_NS
from .source_ids import validate_source_id
from .vda_schemas import VdaMessageFamily

REPORTED_CONNECTION_STATE_DURATION_FUNCTION_ID = (
    "vda.reported_connection_state_duration"
)
REPORTED_CONNECTION_STATE_DURATION_VERSION = "0.1.0"
REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID = (
    f"{REPORTED_CONNECTION_STATE_DURATION_FUNCTION_ID}"
    f"@{REPORTED_CONNECTION_STATE_DURATION_VERSION}"
)
REPORTED_DRIVING_DURATION_FUNCTION_ID = "vda.reported_driving_duration"
REPORTED_DRIVING_DURATION_VERSION = "0.1.0"
REPORTED_DRIVING_DURATION_QUALIFIED_ID = (
    f"{REPORTED_DRIVING_DURATION_FUNCTION_ID}"
    f"@{REPORTED_DRIVING_DURATION_VERSION}"
)
REPORTED_OPERATING_MODE_DURATION_FUNCTION_ID = (
    "vda.reported_operating_mode_duration"
)
REPORTED_PAUSED_DURATION_FUNCTION_ID = "vda.reported_paused_duration"
REPORTED_CHARGING_DURATION_FUNCTION_ID = "vda.reported_charging_duration"
REPORTED_BATTERY_STATE_OF_CHARGE_FUNCTION_ID = (
    "vda.reported_battery_state_of_charge"
)
REPORTED_SAFETY_STATE_DURATION_FUNCTION_ID = (
    "vda.reported_safety_state_duration"
)
_ADDITIONAL_REPORTED_FUNCTION_VERSION = "0.1.0"

REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID = (
    f"{REPORTED_OPERATING_MODE_DURATION_FUNCTION_ID}"
    f"@{_ADDITIONAL_REPORTED_FUNCTION_VERSION}"
)
REPORTED_PAUSED_DURATION_QUALIFIED_ID = (
    f"{REPORTED_PAUSED_DURATION_FUNCTION_ID}"
    f"@{_ADDITIONAL_REPORTED_FUNCTION_VERSION}"
)
REPORTED_CHARGING_DURATION_QUALIFIED_ID = (
    f"{REPORTED_CHARGING_DURATION_FUNCTION_ID}"
    f"@{_ADDITIONAL_REPORTED_FUNCTION_VERSION}"
)
REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID = (
    f"{REPORTED_BATTERY_STATE_OF_CHARGE_FUNCTION_ID}"
    f"@{_ADDITIONAL_REPORTED_FUNCTION_VERSION}"
)
REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID = (
    f"{REPORTED_SAFETY_STATE_DURATION_FUNCTION_ID}"
    f"@{_ADDITIONAL_REPORTED_FUNCTION_VERSION}"
)

MAX_REPORTED_DURATION_DIAGNOSTICS = 256
MAX_REPORTED_DURATION_SUMMARY_DIAGNOSTICS = 32
MAX_REPORTED_DURATION_TERMINAL_DIAGNOSTICS = 2
MAX_REPORTED_DURATION_INPUT_REFERENCES = 256
MAX_REPORTED_DURATION_INTERVAL_DETAILS = 256
MAX_REPORTED_DURATION_TOPIC_CHARACTERS = 4_096

_UNKNOWN = "UNKNOWN"
_DRIVING = "driving"
_NOT_DRIVING = "not_driving"
_HIBERNATING = "HIBERNATING"
_CONNECTION_STATES = (
    "ONLINE",
    "OFFLINE",
    _HIBERNATING,
    "CONNECTION_BROKEN",
)
_OPERATING_MODES = (
    "STARTUP",
    "AUTOMATIC",
    "SEMIAUTOMATIC",
    "INTERVENED",
    "MANUAL",
    "SERVICE",
    "TEACH_IN",
)
_SAFETY_STATES = tuple(
    f"emergency_stop={emergency};field_violation={str(violation).lower()}"
    for emergency in ("MANUAL", "REMOTE", "NONE")
    for violation in (False, True)
)
_OBSERVED = "observed"


class ReportedDurationDiagnosticCode(StrEnum):
    """Classify deterministic reported-duration completeness diagnostics."""

    WINDOW_UNDEFINED = "WINDOW_UNDEFINED"
    INPUT_CHANGED = "INPUT_CHANGED"
    CAPTURE_INCOMPLETE = "CAPTURE_INCOMPLETE"
    CAPTURE_STRUCTURALLY_COMPROMISED = "CAPTURE_STRUCTURALLY_COMPROMISED"
    CAPTURE_RECORD_INVALID = "CAPTURE_RECORD_INVALID"
    CAPTURE_MESSAGE_REJECTED = "CAPTURE_MESSAGE_REJECTED"
    VDA_MESSAGE_INVALID = "VDA_MESSAGE_INVALID"
    UTC_TIME_REGRESSION = "UTC_TIME_REGRESSION"
    COLLECTOR_SESSION_BOUNDARY = "COLLECTOR_SESSION_BOUNDARY"
    COLLECTOR_DROP = "COLLECTOR_DROP"
    MESSAGE_DISCONTINUITY = "MESSAGE_DISCONTINUITY"
    NO_TARGET_OBSERVATION = "NO_TARGET_OBSERVATION"
    HIBERNATION_ENDED = "HIBERNATION_ENDED"
    STATE_CARRY_FORWARD_EXPIRED = "STATE_CARRY_FORWARD_EXPIRED"
    RETAINED_STATE_IGNORED = "RETAINED_STATE_IGNORED"
    STATE_DURING_HIBERNATION = "STATE_DURING_HIBERNATION"
    PRODUCER_DUPLICATE_FLAG = "PRODUCER_DUPLICATE_FLAG"
    EXACT_RETRANSMISSION = "EXACT_RETRANSMISSION"
    HEADER_OUT_OF_RANGE = "HEADER_OUT_OF_RANGE"
    HEADER_GAP = "HEADER_GAP"
    HEADER_REGRESSION = "HEADER_REGRESSION"
    HEADER_CONFLICT = "HEADER_CONFLICT"
    TARGET_TOPIC_CHANGED = "TARGET_TOPIC_CHANGED"
    REQUIRED_FIELD_MISSING = "REQUIRED_FIELD_MISSING"
    INTERVAL_DETAILS_TRUNCATED = "INTERVAL_DETAILS_TRUNCATED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    DIAGNOSTICS_TRUNCATED = "DIAGNOSTICS_TRUNCATED"


@dataclass(frozen=True, slots=True)
class _HeaderBaseline:
    """Retain one accepted per-family topic and header identity."""

    topic: str | None
    header_id: int
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class _ReferenceCandidate:
    """Retain bounded record identity until the input digest is verified."""

    locator: str
    message_family: str
    topic: str | None
    header_identity: str | None


class _RecordedRobotDurationExecutor:
    """Share strict recorded lifecycle handling across robot duration functions."""

    function_id: str
    function_version: str
    relevant_families: frozenset[VdaMessageFamily]
    duration_categories: tuple[str, ...]
    expiring_categories: frozenset[str] = frozenset()

    def __init__(self, source_id: str, robot_target: RobotTarget) -> None:
        """Initialize bounded calculation state for one source and robot target."""

        validate_source_id(source_id)
        if not isinstance(robot_target, RobotTarget):
            raise TypeError("robot_target must be a RobotTarget")
        self._source_id = source_id
        self._target = robot_target
        self._finished = False
        self._input_changed = False
        self._capture_start_ns: int | None = None
        self._capture_end_ns: int | None = None
        self._maximum_observation_time_ns: int | None = None
        self._active_epoch: int | None = None
        self._headers: dict[VdaMessageFamily, _HeaderBaseline] = {}
        self._classification = _UNKNOWN
        self._classification_reason = (
            ReportedDurationDiagnosticCode.NO_TARGET_OBSERVATION
        )
        self._classification_start_ns: int | None = None
        self._state_expiry_ns: int | None = None
        self._durations_ns = {
            category: 0 for category in self.duration_categories
        }
        self._missing_intervals = BoundedIntervalAccumulator(
            MAX_REPORTED_DURATION_INTERVAL_DETAILS
        )
        self._hibernation_intervals = BoundedIntervalAccumulator(
            MAX_REPORTED_DURATION_INTERVAL_DETAILS
        )
        self._partial = False
        self._diagnostics: list[str] = []
        self._diagnostic_seen: set[str] = set()
        self._diagnostics_truncated = False
        self._summary_diagnostics: list[str] = []
        self._summary_diagnostic_seen: set[str] = set()
        self._terminal_diagnostics: list[str] = []
        self._terminal_diagnostic_seen: set[str] = set()
        self._reference_candidates: list[_ReferenceCandidate] = []
        self._reference_candidate_seen: set[_ReferenceCandidate] = set()

    def consume(self, observation: RecordedObservation) -> None:
        """Consume one normalized fact in its original capture order."""

        if self._finished:
            raise RuntimeError("reported-duration executor is already finished")
        if observation.source_id != self._source_id:
            raise ValueError("observation source does not match executor source")
        if isinstance(observation, InputMutationObservation):
            self._input_changed = True
            self._append_terminal_diagnostic(
                ReportedDurationDiagnosticCode.INPUT_CHANGED
            )
            return
        if isinstance(observation, CaptureDiscontinuityObservation):
            self._consume_capture_discontinuity(observation)
            return

        effective_time_ns, regressed = self._effective_time(
            observation.observation_time_ns,
            observation.locator,
        )
        capture_codes = getattr(observation, "capture_diagnostic_codes", ())
        self._record_capture_codes(capture_codes, observation.locator)
        if regressed and self._classification_start_ns is not None:
            self._advance_for_expiry(effective_time_ns)
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.UTC_TIME_REGRESSION,
            )

        if isinstance(observation, CaptureBoundaryObservation):
            self._consume_capture_boundary(observation, effective_time_ns)
        elif isinstance(observation, CollectorSessionObservation):
            self._consume_session_boundary(observation, effective_time_ns)
        elif isinstance(observation, CollectorDropObservation):
            self._advance_for_expiry(effective_time_ns)
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.COLLECTOR_DROP,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.COLLECTOR_DROP,
            )
        elif isinstance(observation, MessageDiscontinuityObservation):
            self._consume_message_discontinuity(
                observation,
                effective_time_ns,
                regressed,
            )
        elif isinstance(observation, NormalizedVdaObservation):
            self._consume_valid_message(
                observation,
                effective_time_ns,
                not regressed,
            )
        else:
            raise TypeError(
                "unsupported recorded observation: "
                f"{type(observation).__name__}"
            )

    def finish(
        self, summary: NormalizedCaptureSummary | None
    ) -> FunctionResult:
        """Finalize after verified exhaustion or an input-mutation failure."""

        if self._finished:
            raise RuntimeError("reported-duration executor is already finished")
        self._finished = True
        if summary is not None and summary.source_id != self._source_id:
            raise ValueError("capture summary source does not match executor source")
        if summary is not None:
            self._record_summary_state(summary)
        if self._input_changed or summary is None or not summary.verified_unchanged:
            self._append_terminal_diagnostic(
                ReportedDurationDiagnosticCode.INPUT_CHANGED
            )
            return self._not_computable()
        if (
            self._capture_start_ns is None
            or self._capture_end_ns is None
            or self._capture_end_ns <= self._capture_start_ns
            or (
                self._maximum_observation_time_ns is not None
                and self._capture_end_ns < self._maximum_observation_time_ns
            )
        ):
            self._append_terminal_diagnostic(
                ReportedDurationDiagnosticCode.WINDOW_UNDEFINED
            )
            return self._not_computable()

        window = EvaluationWindow(self._capture_start_ns, self._capture_end_ns)
        self._advance_for_expiry(window.end_ns)
        self._close_classification(window.end_ns)
        return self._computed_or_partial_result(summary, window)

    def _consume_capture_boundary(
        self,
        observation: CaptureBoundaryObservation,
        effective_time_ns: int,
    ) -> None:
        """Record capture endpoints without treating them as robot messages."""

        if observation.kind is CaptureBoundaryKind.START:
            self._capture_start_ns = observation.observation_time_ns
            self._classification_start_ns = effective_time_ns
            return
        self._advance_for_expiry(effective_time_ns)
        self._capture_end_ns = observation.observation_time_ns
        if observation.declared_complete is not True:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.CAPTURE_INCOMPLETE
            )

    def _consume_session_boundary(
        self,
        observation: CollectorSessionObservation,
        effective_time_ns: int,
    ) -> None:
        """Reset per-epoch headers and break robot signal continuity."""

        self._advance_for_expiry(effective_time_ns)
        self._headers.clear()
        self._state_expiry_ns = None
        if observation.kind is SessionBoundaryKind.START:
            if self._classification != _UNKNOWN:
                self._set_unknown(
                    effective_time_ns,
                    ReportedDurationDiagnosticCode.COLLECTOR_SESSION_BOUNDARY,
                )
            self._active_epoch = observation.continuity_epoch
        else:
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.COLLECTOR_SESSION_BOUNDARY,
            )
            self._active_epoch = None

    def _consume_capture_discontinuity(
        self, observation: CaptureDiscontinuityObservation
    ) -> None:
        """Break continuity conservatively when a record cannot be typed."""

        effective_time_ns = self._maximum_observation_time_ns
        if observation.observation_time_ns is not None:
            effective_time_ns, _ = self._effective_time(
                observation.observation_time_ns,
                observation.locator,
            )
        if effective_time_ns is not None:
            self._advance_for_expiry(effective_time_ns)
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.CAPTURE_RECORD_INVALID,
            )
        self._append_diagnostic(
            ReportedDurationDiagnosticCode.CAPTURE_RECORD_INVALID,
            observation.locator,
        )
        if "UTC_TIME_REGRESSION" in observation.diagnostic_codes:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.UTC_TIME_REGRESSION,
                observation.locator,
            )

    def _consume_message_discontinuity(
        self,
        observation: MessageDiscontinuityObservation,
        effective_time_ns: int,
        regressed: bool,
    ) -> None:
        """Keep relevant invalidity diagnostic without creating a transition."""

        if observation.message_family not in self.relevant_families:
            return
        self._append_reference(
            observation.locator,
            observation.message_family.value,
            observation.topic,
            None,
        )
        if not observation.capture_accepted:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.CAPTURE_MESSAGE_REJECTED,
                observation.locator,
            )
        if not observation.vda_valid:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.VDA_MESSAGE_INVALID,
                observation.locator,
            )
        if not regressed:
            self._advance_for_expiry(effective_time_ns)
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.MESSAGE_DISCONTINUITY,
            )

    def _consume_valid_message(
        self,
        observation: NormalizedVdaObservation,
        effective_time_ns: int,
        transition_allowed: bool,
    ) -> None:
        """Route one exact-target valid message in a concrete executor."""

        raise NotImplementedError

    def _computed_or_partial_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
    ) -> FunctionResult:
        """Build one result after a concrete executor finalizes arithmetic."""

        raise NotImplementedError

    def _matches_target(self, observation: NormalizedVdaObservation) -> bool:
        """Match exact VDA identity without topic parsing or concatenation."""

        return observation.robot_identity == self._target.robot_identity

    def _effective_time(self, time_ns: int, locator: str) -> tuple[int, bool]:
        """Preserve input order and map a regressed coordinate to discontinuity."""

        maximum = self._maximum_observation_time_ns
        if maximum is None:
            self._maximum_observation_time_ns = time_ns
            return time_ns, False
        if time_ns < maximum:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.UTC_TIME_REGRESSION,
                locator,
            )
            return maximum, True
        self._maximum_observation_time_ns = time_ns
        return time_ns, False

    def _advance_for_expiry(self, end_ns: int) -> None:
        """Expire a carried state at exactly the frozen 30-second boundary."""

        expiry = self._state_expiry_ns
        if (
            expiry is not None
            and self._classification in self.expiring_categories
            and expiry <= end_ns
        ):
            self._set_unknown(
                expiry,
                ReportedDurationDiagnosticCode.STATE_CARRY_FORWARD_EXPIRED,
            )
            self._state_expiry_ns = None

    def _set_classification(
        self,
        classification: str,
        time_ns: int,
        reason: ReportedDurationDiagnosticCode | None = None,
    ) -> None:
        """Change the current classification after closing its exact interval."""

        if self._classification_start_ns is None:
            self._classification_start_ns = time_ns
        if (
            classification == self._classification
            and reason == self._classification_reason
        ):
            return
        self._close_classification(time_ns)
        self._classification = classification
        self._classification_reason = reason
        self._classification_start_ns = time_ns

    def _set_unknown(
        self,
        time_ns: int,
        reason: ReportedDurationDiagnosticCode,
    ) -> None:
        """Break trusted state without inventing a replacement value."""

        self._state_expiry_ns = None
        self._set_classification(_UNKNOWN, time_ns, reason)

    def _close_classification(self, end_ns: int) -> None:
        """Accumulate one exact forward classification interval."""

        start_ns = self._classification_start_ns
        if start_ns is None or end_ns <= start_ns:
            return
        duration_ns = end_ns - start_ns
        self._durations_ns[self._classification] += duration_ns
        if self._classification == _UNKNOWN:
            reason = self._classification_reason or (
                ReportedDurationDiagnosticCode.NO_TARGET_OBSERVATION
            )
            first_truncation = self._missing_intervals.add(
                start_ns,
                end_ns,
                reason.value,
            )
            self._append_summary_diagnostic(reason)
            if first_truncation:
                self._append_summary_diagnostic(
                    ReportedDurationDiagnosticCode.INTERVAL_DETAILS_TRUNCATED
                )
        elif self._classification == _HIBERNATING:
            first_truncation = self._hibernation_intervals.add(
                start_ns,
                end_ns,
                "CONFIRMED_HIBERNATION",
            )
            if first_truncation:
                self._append_summary_diagnostic(
                    ReportedDurationDiagnosticCode.INTERVAL_DETAILS_TRUNCATED
                )
        self._classification_start_ns = end_ns

    def _accept_header(
        self, observation: NormalizedVdaObservation, effective_time_ns: int
    ) -> bool:
        """Apply bounded per-family header sequencing for one exact target."""

        if (
            observation.topic is not None
            and len(observation.topic) > MAX_REPORTED_DURATION_TOPIC_CHARACTERS
        ):
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.RESOURCE_LIMIT,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.RESOURCE_LIMIT,
            )
            return False
        if not 0 <= observation.header_id <= MAX_VDA_HEADER_ID:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.HEADER_OUT_OF_RANGE,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.HEADER_OUT_OF_RANGE,
            )
            return False

        previous = self._headers.get(observation.message_family)
        if previous is None:
            self._headers[observation.message_family] = _HeaderBaseline(
                observation.topic,
                observation.header_id,
                observation.payload_sha256,
            )
            return True
        if observation.topic != previous.topic:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.TARGET_TOPIC_CHANGED,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.TARGET_TOPIC_CHANGED,
            )
            return False
        if observation.header_id == previous.header_id:
            if observation.payload_sha256 == previous.payload_sha256:
                self._append_diagnostic(
                    ReportedDurationDiagnosticCode.EXACT_RETRANSMISSION,
                    observation.locator,
                    partial=False,
                )
            else:
                self._append_diagnostic(
                    ReportedDurationDiagnosticCode.HEADER_CONFLICT,
                    observation.locator,
                )
                self._set_unknown(
                    effective_time_ns,
                    ReportedDurationDiagnosticCode.HEADER_CONFLICT,
                )
            return False
        if observation.header_id < previous.header_id:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.HEADER_REGRESSION,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.HEADER_REGRESSION,
            )
            return False
        if observation.header_id > previous.header_id + 1:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.HEADER_GAP,
                observation.locator,
            )
        self._headers[observation.message_family] = _HeaderBaseline(
            observation.topic,
            observation.header_id,
            observation.payload_sha256,
        )
        return True

    def _record_duplicate_flag(
        self, observation: NormalizedVdaObservation
    ) -> None:
        """Report the producer DUP flag without using it as deduplication proof."""

        if observation.producer_duplicate is True:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.PRODUCER_DUPLICATE_FLAG,
                observation.locator,
                partial=False,
            )

    def _append_reference(
        self,
        locator: str,
        message_family: str,
        topic: str | None,
        header_identity: str | None,
    ) -> None:
        """Retain one bounded exact-input reference candidate."""

        candidate = _ReferenceCandidate(
            locator,
            message_family,
            topic,
            header_identity,
        )
        if candidate in self._reference_candidate_seen:
            return
        if len(self._reference_candidates) >= MAX_REPORTED_DURATION_INPUT_REFERENCES:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.RESOURCE_LIMIT,
                locator,
            )
            return
        self._reference_candidates.append(candidate)
        self._reference_candidate_seen.add(candidate)

    def _append_message_reference(
        self, observation: NormalizedVdaObservation
    ) -> None:
        """Retain a safe header identity for one exact-target valid message."""

        header_identity = (
            f"headerId:{observation.header_id}"
            if 0 <= observation.header_id <= MAX_VDA_HEADER_ID
            else "headerId:out-of-range"
        )
        self._append_reference(
            observation.locator,
            observation.message_family.value,
            observation.topic,
            header_identity,
        )

    def _input_references(self, input_sha256: str) -> tuple[InputReference, ...]:
        """Bind retained candidates to the verified capture digest."""

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

    def _coverage(
        self, window: EvaluationWindow, eligible_duration_ns: int
    ) -> Coverage:
        """Build exact coverage from the same UNKNOWN intervals as the value."""

        missing_duration_ns = self._missing_intervals.exact_union_duration_ns(
            window
        )
        if missing_duration_ns is None:
            raise RuntimeError(
                "reported-duration coverage union became unsupported"
            )
        if missing_duration_ns != self._durations_ns[_UNKNOWN]:
            raise RuntimeError(
                "reported-duration missing intervals disagree with duration"
            )
        return Coverage(
            eligible_duration_ns=eligible_duration_ns,
            observed_duration_ns=eligible_duration_ns - missing_duration_ns,
            missing_intervals=tuple(
                MissingInterval(item.start_ns, item.end_ns, item.reason)
                for item in self._missing_intervals.retained_intervals(window)
            ),
            known_missing_interval_count=(
                self._missing_intervals.known_interval_count
            ),
            missing_interval_details_truncated=(
                self._missing_intervals.details_truncated
            ),
        )

    def _record_capture_codes(self, codes: tuple[str, ...], locator: str) -> None:
        """Map capture timing and completeness codes into result diagnostics."""

        for code in codes:
            if code == "UTC_TIME_REGRESSION":
                self._append_diagnostic(
                    ReportedDurationDiagnosticCode.UTC_TIME_REGRESSION,
                    locator,
                )
            elif code == "CAPTURE_DECLARED_INCOMPLETE":
                self._append_summary_diagnostic(
                    ReportedDurationDiagnosticCode.CAPTURE_INCOMPLETE
                )
            else:
                self._append_diagnostic(
                    ReportedDurationDiagnosticCode.CAPTURE_STRUCTURALLY_COMPROMISED,
                    locator,
                )

    def _record_summary_state(self, summary: NormalizedCaptureSummary) -> None:
        """Apply file-level completion facts before result creation."""

        if summary.structurally_compromised:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.CAPTURE_STRUCTURALLY_COMPROMISED
            )
        if not summary.complete:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.CAPTURE_INCOMPLETE
            )
        for code, locator in summary.diagnostic_codes:
            if code == "UTC_TIME_REGRESSION":
                self._append_diagnostic(
                    ReportedDurationDiagnosticCode.UTC_TIME_REGRESSION,
                    locator,
                )

    def _append_diagnostic(
        self,
        code: ReportedDurationDiagnosticCode,
        locator: str | None = None,
        *,
        partial: bool = True,
    ) -> None:
        """Append one unique bounded event diagnostic."""

        if partial:
            self._partial = True
        rendered = code.value if locator is None else f"{code.value}@{locator}"
        if rendered in self._diagnostic_seen:
            return
        if len(self._diagnostics) < MAX_REPORTED_DURATION_DIAGNOSTICS:
            self._diagnostics.append(rendered)
            self._diagnostic_seen.add(rendered)
        else:
            self._diagnostics_truncated = True
            self._partial = True

    def _append_summary_diagnostic(
        self, code: ReportedDurationDiagnosticCode
    ) -> None:
        """Retain one bounded calculation-summary diagnostic."""

        self._partial = True
        rendered = code.value
        if rendered in self._summary_diagnostic_seen:
            return
        if (
            len(self._summary_diagnostics)
            >= MAX_REPORTED_DURATION_SUMMARY_DIAGNOSTICS
        ):
            raise RuntimeError(
                "reported-duration summary diagnostic bound is inconsistent"
            )
        self._summary_diagnostics.append(rendered)
        self._summary_diagnostic_seen.add(rendered)

    def _append_terminal_diagnostic(
        self, code: ReportedDurationDiagnosticCode
    ) -> None:
        """Retain a terminal reason outside the event-detail allowance."""

        if code not in {
            ReportedDurationDiagnosticCode.INPUT_CHANGED,
            ReportedDurationDiagnosticCode.WINDOW_UNDEFINED,
        }:
            raise ValueError("diagnostic code is not a terminal reason")
        rendered = code.value
        if rendered in self._terminal_diagnostic_seen:
            return
        if (
            len(self._terminal_diagnostics)
            >= MAX_REPORTED_DURATION_TERMINAL_DIAGNOSTICS
        ):
            raise RuntimeError(
                "reported-duration terminal diagnostic bound is inconsistent"
            )
        self._terminal_diagnostics.append(rendered)
        self._terminal_diagnostic_seen.add(rendered)

    def _diagnostic_values(self) -> tuple[str, ...]:
        """Return event, truncation, summary, and terminal reasons in order."""

        values = list(self._diagnostics)
        if self._diagnostics_truncated:
            values.append(
                ReportedDurationDiagnosticCode.DIAGNOSTICS_TRUNCATED.value
            )
        values.extend(self._summary_diagnostics)
        values.extend(self._terminal_diagnostics)
        return tuple(values)

    def _not_computable(self) -> FunctionResult:
        """Return a robot-scoped absence without inventing a window or value."""

        return FunctionResult(
            function_id=self.function_id,
            function_version=self.function_version,
            status=ResultStatus.NOT_COMPUTABLE,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, (self._target.subject_id,)),
            window=None,
            coverage=Coverage(0, 0),
            method_version=self.function_version,
            value=None,
            unit=None,
            numerator=None,
            denominator=None,
            input_references=(),
            diagnostics=self._diagnostic_values(),
        )


class ReportedConnectionStateDurationExecutor(_RecordedRobotDurationExecutor):
    """Integrate exact-target reported connection states from receipt time."""

    function_id = REPORTED_CONNECTION_STATE_DURATION_FUNCTION_ID
    function_version = REPORTED_CONNECTION_STATE_DURATION_VERSION
    relevant_families = frozenset({VdaMessageFamily.CONNECTION})
    duration_categories = (*_CONNECTION_STATES, _UNKNOWN)

    def _consume_valid_message(
        self,
        observation: NormalizedVdaObservation,
        effective_time_ns: int,
        transition_allowed: bool,
    ) -> None:
        """Apply one trustworthy target connection transition."""

        if (
            observation.message_family is not VdaMessageFamily.CONNECTION
            or not self._matches_target(observation)
        ):
            return
        self._append_message_reference(observation)
        self._advance_for_expiry(effective_time_ns)
        if not transition_allowed:
            return
        if observation.continuity_epoch != self._active_epoch:
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.COLLECTOR_SESSION_BOUNDARY,
            )
            return
        self._record_duplicate_flag(observation)
        if not self._accept_header(observation, effective_time_ns):
            return
        state = observation.validated_payload.get("connectionState")
        if state not in _CONNECTION_STATES:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
            )
            return
        self._set_classification(str(state), effective_time_ns)

    def _computed_or_partial_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
    ) -> FunctionResult:
        """Build connection-state durations and exact eligible coverage."""

        coverage = self._coverage(window, window.duration_ns)
        hibernation_intervals = self._hibernation_intervals.retained_intervals(
            window
        )
        if self._hibernation_intervals.details_truncated:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.INTERVAL_DETAILS_TRUNCATED
            )
        status = ResultStatus.PARTIAL if self._partial else ResultStatus.COMPUTED
        return FunctionResult(
            function_id=self.function_id,
            function_version=self.function_version,
            status=status,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, (self._target.subject_id,)),
            window=window,
            coverage=coverage,
            method_version=self.function_version,
            value={
                "robot_identity": self._target.robot_identity.to_dict(),
                "durations_ns": dict(self._durations_ns),
                "expected_state_silence_intervals": [
                    item.to_dict() for item in hibernation_intervals
                ],
                "expected_state_silence_interval_count": (
                    self._hibernation_intervals.known_interval_count
                ),
                "expected_state_silence_interval_details_truncated": (
                    self._hibernation_intervals.details_truncated
                ),
            },
            unit="nanoseconds",
            numerator=None,
            denominator=None,
            input_references=self._input_references(summary.input_sha256),
            diagnostics=self._diagnostic_values(),
        )


class ReportedDrivingDurationExecutor(_RecordedRobotDurationExecutor):
    """Integrate exact-target reported driving with bounded carry-forward."""

    function_id = REPORTED_DRIVING_DURATION_FUNCTION_ID
    function_version = REPORTED_DRIVING_DURATION_VERSION
    relevant_families = frozenset(
        {VdaMessageFamily.CONNECTION, VdaMessageFamily.STATE}
    )
    duration_categories = (_DRIVING, _NOT_DRIVING, _UNKNOWN, _HIBERNATING)
    expiring_categories = frozenset({_DRIVING, _NOT_DRIVING})

    def _consume_valid_message(
        self,
        observation: NormalizedVdaObservation,
        effective_time_ns: int,
        transition_allowed: bool,
    ) -> None:
        """Apply one trustworthy target state or connection message."""

        if (
            observation.message_family not in self.relevant_families
            or not self._matches_target(observation)
        ):
            return
        self._append_message_reference(observation)
        self._advance_for_expiry(effective_time_ns)
        if not transition_allowed:
            return
        if observation.continuity_epoch != self._active_epoch:
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.COLLECTOR_SESSION_BOUNDARY,
            )
            return
        self._record_duplicate_flag(observation)
        if observation.message_family is VdaMessageFamily.CONNECTION:
            self._consume_connection(observation, effective_time_ns)
        else:
            self._consume_state(observation, effective_time_ns)

    def _consume_connection(
        self, observation: NormalizedVdaObservation, effective_time_ns: int
    ) -> None:
        """Apply target hibernation state under connection header sequencing."""

        if not self._accept_header(observation, effective_time_ns):
            return
        state = observation.validated_payload.get("connectionState")
        if state not in _CONNECTION_STATES:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
            )
            return
        if state == _HIBERNATING:
            self._state_expiry_ns = None
            self._set_classification(_HIBERNATING, effective_time_ns)
        elif self._classification == _HIBERNATING:
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.HIBERNATION_ENDED,
            )
        elif state in {"OFFLINE", "CONNECTION_BROKEN"}:
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.MESSAGE_DISCONTINUITY,
            )

    def _consume_state(
        self, observation: NormalizedVdaObservation, effective_time_ns: int
    ) -> None:
        """Apply reported driving without using any movement proxy."""

        if observation.retained is True:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.RETAINED_STATE_IGNORED,
                observation.locator,
                partial=False,
            )
            return
        if self._classification == _HIBERNATING:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.STATE_DURING_HIBERNATION,
                observation.locator,
            )
            return
        if not self._accept_header(observation, effective_time_ns):
            return
        driving = observation.validated_payload.get("driving")
        if not isinstance(driving, bool):
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
            )
            return
        self._set_classification(
            _DRIVING if driving else _NOT_DRIVING,
            effective_time_ns,
        )
        self._state_expiry_ns = effective_time_ns + STATE_CARRY_FORWARD_NS

    def _computed_or_partial_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
    ) -> FunctionResult:
        """Build driving durations with hibernation excluded from eligibility."""

        excluded_duration_ns = self._hibernation_intervals.exact_union_duration_ns(
            window
        )
        if excluded_duration_ns is None:
            raise RuntimeError(
                "reported-driving hibernation union became unsupported"
            )
        if excluded_duration_ns != self._durations_ns[_HIBERNATING]:
            raise RuntimeError(
                "reported-driving hibernation intervals disagree with duration"
            )
        coverage = self._coverage(
            window,
            window.duration_ns - excluded_duration_ns,
        )
        expected_observed = (
            self._durations_ns[_DRIVING] + self._durations_ns[_NOT_DRIVING]
        )
        if coverage.observed_duration_ns != expected_observed:
            raise RuntimeError(
                "reported-driving values disagree with observed coverage"
            )
        excluded_intervals = self._hibernation_intervals.retained_intervals(
            window
        )
        if self._hibernation_intervals.details_truncated:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.INTERVAL_DETAILS_TRUNCATED
            )
        status = ResultStatus.PARTIAL if self._partial else ResultStatus.COMPUTED
        return FunctionResult(
            function_id=self.function_id,
            function_version=self.function_version,
            status=status,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, (self._target.subject_id,)),
            window=window,
            coverage=coverage,
            method_version=self.function_version,
            value={
                "robot_identity": self._target.robot_identity.to_dict(),
                "durations_ns": {
                    _DRIVING: self._durations_ns[_DRIVING],
                    _NOT_DRIVING: self._durations_ns[_NOT_DRIVING],
                    _UNKNOWN: self._durations_ns[_UNKNOWN],
                },
                "excluded_intervals": [
                    item.to_dict() for item in excluded_intervals
                ],
                "excluded_interval_count": (
                    self._hibernation_intervals.known_interval_count
                ),
                "excluded_interval_details_truncated": (
                    self._hibernation_intervals.details_truncated
                ),
            },
            unit="nanoseconds",
            numerator=None,
            denominator=None,
            input_references=self._input_references(summary.input_sha256),
            diagnostics=self._diagnostic_values(),
        )


class ReportedStateDurationKind(StrEnum):
    """Select one statically defined VDA state-duration calculation."""

    OPERATING_MODE = "operating_mode"
    PAUSED = "paused"
    CHARGING = "charging"
    SAFETY_STATE = "safety_state"


class ReportedStateDurationExecutor(ReportedDrivingDurationExecutor):
    """Integrate one declared VDA state field with shared missingness rules."""

    def __init__(
        self,
        source_id: str,
        robot_target: RobotTarget,
        kind: ReportedStateDurationKind,
    ) -> None:
        """Configure one first-party state-duration function."""

        if not isinstance(kind, ReportedStateDurationKind):
            raise TypeError("kind must be a ReportedStateDurationKind")
        self._kind = kind
        self._accepted_sample_count = 0
        if kind is ReportedStateDurationKind.OPERATING_MODE:
            self.function_id = REPORTED_OPERATING_MODE_DURATION_FUNCTION_ID
            categories = _OPERATING_MODES
        elif kind is ReportedStateDurationKind.PAUSED:
            self.function_id = REPORTED_PAUSED_DURATION_FUNCTION_ID
            categories = ("paused", "not_paused")
        elif kind is ReportedStateDurationKind.CHARGING:
            self.function_id = REPORTED_CHARGING_DURATION_FUNCTION_ID
            categories = ("charging", "not_charging")
        else:
            self.function_id = REPORTED_SAFETY_STATE_DURATION_FUNCTION_ID
            categories = _SAFETY_STATES
        self.function_version = _ADDITIONAL_REPORTED_FUNCTION_VERSION
        self.duration_categories = (*categories, _UNKNOWN, _HIBERNATING)
        self.expiring_categories = frozenset(categories)
        super().__init__(source_id, robot_target)

    def _consume_state(
        self, observation: NormalizedVdaObservation, effective_time_ns: int
    ) -> None:
        """Apply one exact-target state sample for the configured function."""

        if observation.retained is True:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.RETAINED_STATE_IGNORED,
                observation.locator,
                partial=False,
            )
            return
        if self._classification == _HIBERNATING:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.STATE_DURING_HIBERNATION,
                observation.locator,
            )
            return
        if not self._accept_header(observation, effective_time_ns):
            return
        category = self._category(observation.validated_payload)
        if category is None:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
            )
            return
        self._accepted_sample_count += 1
        self._set_classification(category, effective_time_ns)
        self._state_expiry_ns = effective_time_ns + STATE_CARRY_FORWARD_NS

    def _category(self, payload: Mapping[str, object]) -> str | None:
        """Map a validated state object to one declared duration category."""

        if self._kind is ReportedStateDurationKind.OPERATING_MODE:
            mode = payload.get("operatingMode")
            return str(mode) if mode in _OPERATING_MODES else None
        if self._kind is ReportedStateDurationKind.PAUSED:
            paused = payload.get("paused")
            if not isinstance(paused, bool):
                return None
            return "paused" if paused else "not_paused"
        if self._kind is ReportedStateDurationKind.CHARGING:
            power_supply = payload.get("powerSupply")
            if not isinstance(power_supply, Mapping):
                return None
            charging = power_supply.get("charging")
            if not isinstance(charging, bool):
                return None
            return "charging" if charging else "not_charging"
        safety_state = payload.get("safetyState")
        if not isinstance(safety_state, Mapping):
            return None
        emergency = safety_state.get("activeEmergencyStop")
        violation = safety_state.get("fieldViolation")
        if emergency not in {"MANUAL", "REMOTE", "NONE"} or not isinstance(
            violation, bool
        ):
            return None
        return (
            f"emergency_stop={emergency};"
            f"field_violation={str(violation).lower()}"
        )

    def _computed_or_partial_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
    ) -> FunctionResult:
        """Build one state-duration result with exact hibernation exclusion."""

        if self._accepted_sample_count == 0:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING
            )
            return self._not_computable()
        excluded_duration_ns = self._hibernation_intervals.exact_union_duration_ns(
            window
        )
        if excluded_duration_ns is None:
            raise RuntimeError("state-duration hibernation union became unsupported")
        if self._durations_ns[_HIBERNATING] != excluded_duration_ns:
            raise RuntimeError("state-duration exclusions disagree with duration")
        coverage = self._coverage(
            window,
            window.duration_ns - excluded_duration_ns,
        )
        expected_observed = sum(
            self._durations_ns[category]
            for category in self.expiring_categories
        )
        if coverage.observed_duration_ns != expected_observed:
            raise RuntimeError("state-duration values disagree with coverage")
        excluded_intervals = self._hibernation_intervals.retained_intervals(window)
        if self._hibernation_intervals.details_truncated:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.INTERVAL_DETAILS_TRUNCATED
            )
        status = ResultStatus.PARTIAL if self._partial else ResultStatus.COMPUTED
        return FunctionResult(
            function_id=self.function_id,
            function_version=self.function_version,
            status=status,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, (self._target.subject_id,)),
            window=window,
            coverage=coverage,
            method_version=self.function_version,
            value={
                "robot_identity": self._target.robot_identity.to_dict(),
                "durations_ns": {
                    category: self._durations_ns[category]
                    for category in self.duration_categories
                    if category not in {_UNKNOWN, _HIBERNATING}
                }
                | {_UNKNOWN: self._durations_ns[_UNKNOWN]},
                "sample_count": self._accepted_sample_count,
                "excluded_intervals": [
                    item.to_dict() for item in excluded_intervals
                ],
                "excluded_interval_count": (
                    self._hibernation_intervals.known_interval_count
                ),
                "excluded_interval_details_truncated": (
                    self._hibernation_intervals.details_truncated
                ),
            },
            unit="nanoseconds",
            numerator=None,
            denominator=None,
            input_references=self._input_references(summary.input_sha256),
            diagnostics=self._diagnostic_values(),
        )


class ReportedBatteryStateOfChargeExecutor(ReportedDrivingDurationExecutor):
    """Report first, minimum, and last exact-target battery state of charge."""

    function_id = REPORTED_BATTERY_STATE_OF_CHARGE_FUNCTION_ID
    function_version = _ADDITIONAL_REPORTED_FUNCTION_VERSION
    duration_categories = (_OBSERVED, _UNKNOWN, _HIBERNATING)
    expiring_categories = frozenset({_OBSERVED})

    def __init__(self, source_id: str, robot_target: RobotTarget) -> None:
        """Initialize battery sample and shared continuity state."""

        self._first_state_of_charge: float | None = None
        self._minimum_state_of_charge: float | None = None
        self._last_state_of_charge: float | None = None
        self._sample_count = 0
        super().__init__(source_id, robot_target)

    def _consume_state(
        self, observation: NormalizedVdaObservation, effective_time_ns: int
    ) -> None:
        """Accept one trustworthy state-of-charge sample without interpolation."""

        if observation.retained is True:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.RETAINED_STATE_IGNORED,
                observation.locator,
                partial=False,
            )
            return
        if self._classification == _HIBERNATING:
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.STATE_DURING_HIBERNATION,
                observation.locator,
            )
            return
        if not self._accept_header(observation, effective_time_ns):
            return
        power_supply = observation.validated_payload.get("powerSupply")
        state_of_charge = (
            power_supply.get("stateOfCharge")
            if isinstance(power_supply, Mapping)
            else None
        )
        if (
            isinstance(state_of_charge, bool)
            or not isinstance(state_of_charge, (int, float))
            or not 0 <= state_of_charge <= 100
        ):
            self._append_diagnostic(
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
                observation.locator,
            )
            self._set_unknown(
                effective_time_ns,
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING,
            )
            return
        sample = float(state_of_charge)
        if self._first_state_of_charge is None:
            self._first_state_of_charge = sample
            self._minimum_state_of_charge = sample
        else:
            assert self._minimum_state_of_charge is not None
            self._minimum_state_of_charge = min(
                self._minimum_state_of_charge, sample
            )
        self._last_state_of_charge = sample
        self._sample_count += 1
        self._set_classification(_OBSERVED, effective_time_ns)
        self._state_expiry_ns = effective_time_ns + STATE_CARRY_FORWARD_NS

    def _computed_or_partial_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
    ) -> FunctionResult:
        """Build the battery summary and duration-based source coverage."""

        if self._sample_count == 0:
            self._append_summary_diagnostic(
                ReportedDurationDiagnosticCode.REQUIRED_FIELD_MISSING
            )
            return self._not_computable()
        excluded_duration_ns = self._hibernation_intervals.exact_union_duration_ns(
            window
        )
        if excluded_duration_ns is None:
            raise RuntimeError("battery hibernation union became unsupported")
        if self._durations_ns[_HIBERNATING] != excluded_duration_ns:
            raise RuntimeError("battery exclusions disagree with duration")
        coverage = self._coverage(
            window,
            window.duration_ns - excluded_duration_ns,
        )
        if coverage.observed_duration_ns != self._durations_ns[_OBSERVED]:
            raise RuntimeError("battery observation duration disagrees with coverage")
        status = ResultStatus.PARTIAL if self._partial else ResultStatus.COMPUTED
        return FunctionResult(
            function_id=self.function_id,
            function_version=self.function_version,
            status=status,
            basis=ResultBasis.REPORTED,
            scope=ResultScope(ScopeKind.ROBOT, (self._target.subject_id,)),
            window=window,
            coverage=coverage,
            method_version=self.function_version,
            value={
                "robot_identity": self._target.robot_identity.to_dict(),
                "first_percent": self._first_state_of_charge,
                "minimum_percent": self._minimum_state_of_charge,
                "last_percent": self._last_state_of_charge,
                "sample_count": self._sample_count,
            },
            unit="percent",
            numerator=None,
            denominator=None,
            input_references=self._input_references(summary.input_sha256),
            diagnostics=self._diagnostic_values(),
        )
