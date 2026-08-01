"""Bounded cohort functions for observed orders, errors, and lifecycle inference."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
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
from .vda_schemas import FrozenJsonValue, VdaMessageFamily

OBSERVED_ORDERS_FUNCTION_ID = "vda.observed_orders"
ACTIVE_ERROR_EPISODES_FUNCTION_ID = "vda.inferred_active_error_episodes"
PROTOCOL_ORDER_OUTCOMES_FUNCTION_ID = "vda.inferred_protocol_order_outcomes"
PROTOCOL_ORDER_EXECUTION_DURATION_FUNCTION_ID = (
    "vda.inferred_protocol_order_execution_duration"
)
FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_FUNCTION_ID = (
    "vda.inferred_protocol_finished_orders_per_observed_robot_hour"
)
EVENT_FUNCTION_VERSION = "0.1.0"

OBSERVED_ORDERS_QUALIFIED_ID = (
    f"{OBSERVED_ORDERS_FUNCTION_ID}@{EVENT_FUNCTION_VERSION}"
)
ACTIVE_ERROR_EPISODES_QUALIFIED_ID = (
    f"{ACTIVE_ERROR_EPISODES_FUNCTION_ID}@{EVENT_FUNCTION_VERSION}"
)
PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID = (
    f"{PROTOCOL_ORDER_OUTCOMES_FUNCTION_ID}@{EVENT_FUNCTION_VERSION}"
)
PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID = (
    f"{PROTOCOL_ORDER_EXECUTION_DURATION_FUNCTION_ID}@{EVENT_FUNCTION_VERSION}"
)
FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID = (
    f"{FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_FUNCTION_ID}"
    f"@{EVENT_FUNCTION_VERSION}"
)

MAX_EVENT_ROBOTS = 1_024
MAX_EVENT_ORDERS = 10_000
MAX_ORDER_UPDATES = 256
MAX_ERROR_EPISODES = 10_000
MAX_EVENT_DIAGNOSTICS = 256
MAX_EVENT_INPUT_REFERENCES = 512
MAX_EVENT_INTERVAL_DETAILS = 256


class EventFunctionKind(StrEnum):
    """Select one statically compiled cohort event calculation."""

    OBSERVED_ORDERS = "observed_orders"
    ERROR_EPISODES = "error_episodes"
    ORDER_OUTCOMES = "order_outcomes"
    EXECUTION_DURATION = "execution_duration"
    FINISHED_RATE = "finished_rate"


class OrderOutcome(StrEnum):
    """Conservative terminal classifications for one observed robot/order."""

    INFERRED_FINISHED = "INFERRED_FINISHED"
    CANCELED_OR_CLEARED = "CANCELED_OR_CLEARED"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"


class EventDiagnosticCode(StrEnum):
    """Classify completeness and inference limitations without payload text."""

    WINDOW_UNDEFINED = "WINDOW_UNDEFINED"
    NO_RELEVANT_OBSERVATION = "NO_RELEVANT_OBSERVATION"
    INPUT_CHANGED = "INPUT_CHANGED"
    CAPTURE_INCOMPLETE = "CAPTURE_INCOMPLETE"
    CAPTURE_STRUCTURALLY_COMPROMISED = "CAPTURE_STRUCTURALLY_COMPROMISED"
    CAPTURE_RECORD_INVALID = "CAPTURE_RECORD_INVALID"
    MESSAGE_DISCONTINUITY = "MESSAGE_DISCONTINUITY"
    COLLECTOR_SESSION_GAP = "COLLECTOR_SESSION_GAP"
    COLLECTOR_DROP = "COLLECTOR_DROP"
    UTC_TIME_REGRESSION = "UTC_TIME_REGRESSION"
    HEADER_OUT_OF_RANGE = "HEADER_OUT_OF_RANGE"
    HEADER_GAP = "HEADER_GAP"
    HEADER_REGRESSION = "HEADER_REGRESSION"
    HEADER_CONFLICT = "HEADER_CONFLICT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    STATE_CARRY_FORWARD_EXPIRED = "STATE_CARRY_FORWARD_EXPIRED"
    ORDER_CROSSED_DISCONTINUITY = "ORDER_CROSSED_DISCONTINUITY"
    INTERVAL_DETAILS_TRUNCATED = "INTERVAL_DETAILS_TRUNCATED"
    COVERAGE_DURATION_UNAVAILABLE = "COVERAGE_DURATION_UNAVAILABLE"
    DIAGNOSTICS_TRUNCATED = "DIAGNOSTICS_TRUNCATED"


@dataclass(frozen=True, slots=True, order=True)
class _OrderKey:
    """Identify one order independently for each exact VDA robot identity."""

    manufacturer: str
    serial_number: str
    order_id: str


@dataclass(frozen=True, slots=True)
class _OrderProposal:
    """Retain the defensible final released node for one observed update."""

    update_id: int
    final_node_id: str | None
    final_node_sequence_id: int | None
    observed_at_ns: int


@dataclass(slots=True)
class _OrderRecord:
    """Accumulate bounded evidence for one robot/order identity."""

    key: _OrderKey
    first_observed_at_ns: int
    proposals: dict[int, _OrderProposal] = field(default_factory=dict)
    accepted_updates: set[int] = field(default_factory=set)
    accepted_at_ns: int | None = None
    terminal_at_ns: int | None = None
    outcome: OrderOutcome = OrderOutcome.INDETERMINATE
    crossed_discontinuity: bool = False


@dataclass(frozen=True, slots=True, order=True)
class _ErrorIdentity:
    """Canonicalize a raw reported error without descriptions or hints."""

    error_type: str
    error_level: str
    references: tuple[tuple[str, str], ...]


@dataclass(slots=True)
class _ActiveError:
    """Track one continuous observed error episode."""

    identity: _ErrorIdentity
    start_ns: int
    last_observed_ns: int


@dataclass(frozen=True, slots=True)
class _ErrorEpisode:
    """Retain one closed half-open error episode."""

    robot: RobotIdentity
    identity: _ErrorIdentity
    start_ns: int
    end_ns: int


@dataclass(slots=True)
class _RobotObservationState:
    """Track duration where state evidence is continuously observed."""

    last_state_ns: int | None = None
    last_epoch: int | None = None
    observed_duration_ns: int = 0
    hibernating: bool = False


@dataclass(frozen=True, slots=True)
class _HeaderBaseline:
    """Retain one accepted stream header and exact payload identity."""

    header_id: int
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class _ReferenceCandidate:
    """Retain bounded portable record identity until input verification."""

    locator: str
    message_family: str
    topic: str | None
    header_identity: str


class CohortEventExecutor:
    """Calculate one cohort event function in a bounded single pass."""

    def __init__(self, source_id: str, kind: EventFunctionKind) -> None:
        """Initialize one statically selected function for a recorded source."""

        validate_source_id(source_id)
        if not isinstance(kind, EventFunctionKind):
            raise TypeError("kind must be an EventFunctionKind")
        self._source_id = source_id
        self._kind = kind
        self._finished = False
        self._input_changed = False
        self._capture_start_ns: int | None = None
        self._capture_end_ns: int | None = None
        self._maximum_time_ns: int | None = None
        self._active_epoch: int | None = None
        self._session_gap_start_ns: int | None = None
        self._coverage_gaps = BoundedIntervalAccumulator(
            MAX_EVENT_INTERVAL_DETAILS
        )
        self._subjects: dict[RobotIdentity, str] = {}
        self._headers: dict[
            tuple[int, RobotIdentity, VdaMessageFamily, str | None],
            _HeaderBaseline,
        ] = {}
        self._orders: dict[_OrderKey, _OrderRecord] = {}
        self._active_order_by_robot: dict[RobotIdentity, _OrderKey] = {}
        self._pending_clear_actions: dict[
            tuple[RobotIdentity, str], _OrderKey
        ] = {}
        self._active_errors: dict[
            RobotIdentity, dict[_ErrorIdentity, _ActiveError]
        ] = {}
        self._error_episodes: list[_ErrorEpisode] = []
        self._robot_observation: dict[
            RobotIdentity, _RobotObservationState
        ] = {}
        self._diagnostics: list[str] = []
        self._diagnostic_seen: set[str] = set()
        self._diagnostics_truncated = False
        self._partial = False
        self._reference_candidates: list[_ReferenceCandidate] = []
        self._reference_seen: set[_ReferenceCandidate] = set()

    def consume(self, observation: RecordedObservation) -> None:
        """Consume one normalized fact in original capture order."""

        if self._finished:
            raise RuntimeError("cohort event executor is already finished")
        if observation.source_id != self._source_id:
            raise ValueError("observation source does not match executor source")
        if isinstance(observation, InputMutationObservation):
            self._input_changed = True
            self._append_diagnostic(EventDiagnosticCode.INPUT_CHANGED)
            return
        if isinstance(observation, CaptureDiscontinuityObservation):
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.CAPTURE_RECORD_INVALID, observation.locator
            )
            self._taint_active_orders()
            return

        effective_ns, forward = self._effective_time(
            observation.observation_time_ns, observation.locator
        )
        if isinstance(observation, CaptureBoundaryObservation):
            self._consume_capture_boundary(observation, effective_ns)
        elif isinstance(observation, CollectorSessionObservation):
            self._consume_session_boundary(observation, effective_ns)
        elif isinstance(observation, CollectorDropObservation):
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.COLLECTOR_DROP, observation.locator
            )
            self._taint_active_orders()
            self._close_all_errors(effective_ns)
        elif isinstance(observation, MessageDiscontinuityObservation):
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.MESSAGE_DISCONTINUITY,
                observation.locator,
            )
            self._taint_active_orders()
            self._close_all_errors(effective_ns)
        elif isinstance(observation, NormalizedVdaObservation):
            self._consume_message(observation, effective_ns, forward)
        else:
            raise TypeError(f"unsupported observation: {type(observation).__name__}")

    def finish(
        self, summary: NormalizedCaptureSummary | None
    ) -> FunctionResult:
        """Finalize one deterministic cohort result after verified exhaustion."""

        if self._finished:
            raise RuntimeError("cohort event executor is already finished")
        self._finished = True
        if self._input_changed or summary is None:
            return self._not_computable(EventDiagnosticCode.INPUT_CHANGED)
        if summary.source_id != self._source_id:
            raise ValueError("summary source does not match executor source")
        if not summary.complete:
            self._partial = True
            self._append_diagnostic(EventDiagnosticCode.CAPTURE_INCOMPLETE)
        if summary.structurally_compromised:
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.CAPTURE_STRUCTURALLY_COMPROMISED
            )
        window = self._window()
        if window is None:
            return self._not_computable(EventDiagnosticCode.WINDOW_UNDEFINED)
        if self._session_gap_start_ns is not None:
            self._coverage_gaps.add(
                self._session_gap_start_ns,
                window.end_ns,
                EventDiagnosticCode.COLLECTOR_SESSION_GAP.value,
            )
        self._close_all_errors(window.end_ns)
        if self._kind is EventFunctionKind.FINISHED_RATE:
            self._finalize_robot_observation(window.end_ns)
        coverage = self._coverage(window)
        if self._kind is EventFunctionKind.OBSERVED_ORDERS:
            return self._observed_orders_result(summary, window, coverage)
        if self._kind is EventFunctionKind.ERROR_EPISODES:
            return self._error_episodes_result(summary, window, coverage)
        if self._kind is EventFunctionKind.ORDER_OUTCOMES:
            return self._order_outcomes_result(summary, window, coverage)
        if self._kind is EventFunctionKind.EXECUTION_DURATION:
            return self._execution_duration_result(summary, window, coverage)
        return self._finished_rate_result(summary, window, coverage)

    def _effective_time(self, raw_ns: int, locator: str) -> tuple[int, bool]:
        """Clamp regressed capture time while recording the loss of ordering."""

        previous = self._maximum_time_ns
        if previous is None or raw_ns >= previous:
            self._maximum_time_ns = raw_ns
            return raw_ns, True
        self._partial = True
        self._append_diagnostic(EventDiagnosticCode.UTC_TIME_REGRESSION, locator)
        self._taint_active_orders()
        return previous, False

    def _consume_capture_boundary(
        self, observation: CaptureBoundaryObservation, effective_ns: int
    ) -> None:
        """Track one capture boundary and declared completeness."""

        if observation.kind is CaptureBoundaryKind.START:
            if self._capture_start_ns is None:
                self._capture_start_ns = effective_ns
            else:
                self._partial = True
                self._append_diagnostic(EventDiagnosticCode.CAPTURE_RECORD_INVALID)
        else:
            self._capture_end_ns = effective_ns
            if observation.declared_complete is not True:
                self._partial = True
                self._append_diagnostic(EventDiagnosticCode.CAPTURE_INCOMPLETE)

    def _consume_session_boundary(
        self, observation: CollectorSessionObservation, effective_ns: int
    ) -> None:
        """Open or close an accepted collector continuity epoch."""

        self._close_all_errors(effective_ns)
        self._taint_active_orders()
        if observation.kind is SessionBoundaryKind.START:
            if self._session_gap_start_ns is not None:
                if self._coverage_gaps.add(
                    self._session_gap_start_ns,
                    effective_ns,
                    EventDiagnosticCode.COLLECTOR_SESSION_GAP.value,
                ):
                    self._append_diagnostic(
                        EventDiagnosticCode.INTERVAL_DETAILS_TRUNCATED
                    )
                self._session_gap_start_ns = None
            self._active_epoch = observation.continuity_epoch
        else:
            self._active_epoch = None
            self._session_gap_start_ns = effective_ns

    def _consume_message(
        self,
        observation: NormalizedVdaObservation,
        effective_ns: int,
        forward: bool,
    ) -> None:
        """Apply one validated VDA message after continuity and header checks."""

        if not forward or observation.continuity_epoch != self._active_epoch:
            self._partial = True
            self._taint_active_orders()
            return
        if len(self._subjects) >= MAX_EVENT_ROBOTS and (
            observation.robot_identity not in self._subjects
        ):
            self._partial = True
            self._append_diagnostic(EventDiagnosticCode.RESOURCE_LIMIT)
            return
        self._subjects.setdefault(
            observation.robot_identity,
            _subject_id(observation.robot_identity),
        )
        if not self._accept_header(observation):
            return
        self._append_reference(observation)
        family = observation.message_family
        if family is VdaMessageFamily.ORDER:
            self._consume_order(observation, effective_ns)
        elif family is VdaMessageFamily.INSTANT_ACTIONS:
            self._consume_instant_actions(observation)
        elif family is VdaMessageFamily.CONNECTION:
            self._consume_connection(observation, effective_ns)
        elif family is VdaMessageFamily.STATE:
            self._consume_state(observation, effective_ns)

    def _accept_header(self, observation: NormalizedVdaObservation) -> bool:
        """Reject ambiguous stream ordering while allowing forward gaps."""

        if not 0 <= observation.header_id <= MAX_VDA_HEADER_ID:
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.HEADER_OUT_OF_RANGE, observation.locator
            )
            return False
        key = (
            observation.continuity_epoch,
            observation.robot_identity,
            observation.message_family,
            observation.topic,
        )
        previous = self._headers.get(key)
        if previous is None:
            self._headers[key] = _HeaderBaseline(
                observation.header_id, observation.payload_sha256
            )
            return True
        if observation.header_id == previous.header_id:
            if observation.payload_sha256 == previous.payload_sha256:
                return False
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.HEADER_CONFLICT, observation.locator
            )
            return False
        if observation.header_id < previous.header_id:
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.HEADER_REGRESSION, observation.locator
            )
            return False
        if observation.header_id > previous.header_id + 1:
            self._partial = True
            self._append_diagnostic(
                EventDiagnosticCode.HEADER_GAP, observation.locator
            )
            self._taint_active_orders()
        self._headers[key] = _HeaderBaseline(
            observation.header_id, observation.payload_sha256
        )
        return True

    def _consume_order(
        self, observation: NormalizedVdaObservation, effective_ns: int
    ) -> None:
        """Record one order/update proposal without claiming acceptance."""

        payload = observation.validated_payload
        order_id = payload.get("orderId")
        update_id = payload.get("orderUpdateId")
        if not isinstance(order_id, str) or not order_id:
            return
        if isinstance(update_id, bool) or not isinstance(update_id, int):
            return
        key = _OrderKey(
            observation.robot_identity.manufacturer,
            observation.robot_identity.serial_number,
            order_id,
        )
        record = self._orders.get(key)
        if record is None:
            if len(self._orders) >= MAX_EVENT_ORDERS:
                self._partial = True
                self._append_diagnostic(EventDiagnosticCode.RESOURCE_LIMIT)
                return
            record = _OrderRecord(key, effective_ns)
            self._orders[key] = record
        if update_id not in record.proposals:
            if len(record.proposals) >= MAX_ORDER_UPDATES:
                self._partial = True
                record.crossed_discontinuity = True
                self._append_diagnostic(EventDiagnosticCode.RESOURCE_LIMIT)
                return
            final_id, final_sequence = _final_released_node(payload.get("nodes"))
            record.proposals[update_id] = _OrderProposal(
                update_id, final_id, final_sequence, effective_ns
            )

    def _consume_instant_actions(
        self, observation: NormalizedVdaObservation
    ) -> None:
        """Remember cancel/hibernation actions until a finished state reports them."""

        actions = observation.validated_payload.get("actions")
        if not isinstance(actions, Sequence) or isinstance(actions, (str, bytes)):
            return
        robot = observation.robot_identity
        for action in actions:
            if not isinstance(action, Mapping):
                continue
            action_type = action.get("actionType")
            action_id = action.get("actionId")
            if action_type not in {"cancelOrder", "startHibernation"} or not isinstance(
                action_id, str
            ):
                continue
            target: _OrderKey | None = None
            if action_type == "cancelOrder":
                target_id = _action_parameter(action, "orderId")
                if target_id is not None:
                    target = _OrderKey(
                        robot.manufacturer, robot.serial_number, target_id
                    )
            else:
                target = self._active_order_by_robot.get(robot)
            if target is not None and target in self._orders:
                self._pending_clear_actions[(robot, action_id)] = target

    def _consume_connection(
        self, observation: NormalizedVdaObservation, effective_ns: int
    ) -> None:
        """Track hibernation as excluded time and a lifecycle-clearing boundary."""

        state = observation.validated_payload.get("connectionState")
        robot_state = self._robot_observation.setdefault(
            observation.robot_identity, _RobotObservationState()
        )
        if state == "HIBERNATING":
            robot_state.hibernating = True
            self._close_robot_errors(observation.robot_identity, effective_ns)
            active = self._active_order_by_robot.get(observation.robot_identity)
            if active is not None:
                self._mark_terminal(active, OrderOutcome.CANCELED_OR_CLEARED, effective_ns)
        elif state in {"ONLINE", "OFFLINE", "CONNECTION_BROKEN"}:
            robot_state.hibernating = False

    def _consume_state(
        self, observation: NormalizedVdaObservation, effective_ns: int
    ) -> None:
        """Apply reported state to error episodes, observation time, and orders."""

        robot = observation.robot_identity
        self._observe_robot_state(robot, observation.continuity_epoch, effective_ns)
        self._consume_errors(robot, observation.validated_payload, effective_ns)
        self._apply_finished_clear_actions(robot, observation.validated_payload, effective_ns)
        self._apply_rejection_errors(robot, observation.validated_payload, effective_ns)

        order_id = observation.validated_payload.get("orderId")
        update_id = observation.validated_payload.get("orderUpdateId")
        if not isinstance(order_id, str) or not order_id:
            return
        if isinstance(update_id, bool) or not isinstance(update_id, int):
            return
        key = _OrderKey(robot.manufacturer, robot.serial_number, order_id)
        record = self._orders.get(key)
        if record is None or update_id not in record.proposals:
            return
        record.accepted_updates.add(update_id)
        if record.accepted_at_ns is None:
            record.accepted_at_ns = effective_ns
        self._active_order_by_robot[robot] = key
        if record.crossed_discontinuity:
            return
        proposal = record.proposals[update_id]
        if _state_proves_terminal(observation.validated_payload, proposal):
            self._mark_terminal(key, OrderOutcome.INFERRED_FINISHED, effective_ns)

    def _observe_robot_state(
        self, robot: RobotIdentity, epoch: int, effective_ns: int
    ) -> None:
        """Accumulate continuous state-observation duration with bounded carry."""

        state = self._robot_observation.setdefault(robot, _RobotObservationState())
        previous = state.last_state_ns
        if (
            previous is not None
            and state.last_epoch == epoch
            and not state.hibernating
        ):
            delta = max(0, effective_ns - previous)
            if self._kind is EventFunctionKind.FINISHED_RATE:
                state.observed_duration_ns += min(delta, STATE_CARRY_FORWARD_NS)
            if delta > STATE_CARRY_FORWARD_NS:
                active_errors = bool(self._active_errors.get(robot))
                active_order = self._active_order_by_robot.get(robot)
                relevant_gap = (
                    self._kind is EventFunctionKind.FINISHED_RATE
                    or (
                        self._kind is EventFunctionKind.ERROR_EPISODES
                        and active_errors
                    )
                    or (
                        self._kind
                        in {
                            EventFunctionKind.ORDER_OUTCOMES,
                            EventFunctionKind.EXECUTION_DURATION,
                        }
                        and active_order is not None
                    )
                )
                if relevant_gap:
                    self._partial = True
                    self._append_diagnostic(
                        EventDiagnosticCode.STATE_CARRY_FORWARD_EXPIRED
                    )
                if active_errors:
                    self._close_robot_errors(
                        robot, previous + STATE_CARRY_FORWARD_NS
                    )
                if active_order is not None and relevant_gap:
                    record = self._orders.get(active_order)
                    if record is not None:
                        record.crossed_discontinuity = True
        state.last_state_ns = effective_ns
        state.last_epoch = epoch

    def _consume_errors(
        self,
        robot: RobotIdentity,
        payload: Mapping[str, FrozenJsonValue],
        effective_ns: int,
    ) -> None:
        """Open and close raw-error episodes on each trustworthy state sample."""

        raw_errors = payload.get("errors")
        identities: set[_ErrorIdentity] = set()
        if isinstance(raw_errors, Sequence) and not isinstance(
            raw_errors, (str, bytes)
        ):
            for item in raw_errors:
                identity = _error_identity(item)
                if identity is not None:
                    identities.add(identity)
        active = self._active_errors.setdefault(robot, {})
        for identity in tuple(active):
            if identity not in identities:
                self._close_error(robot, identity, effective_ns)
        for identity in sorted(identities):
            current = active.get(identity)
            if current is None:
                active[identity] = _ActiveError(identity, effective_ns, effective_ns)
            else:
                current.last_observed_ns = effective_ns

    def _apply_finished_clear_actions(
        self,
        robot: RobotIdentity,
        payload: Mapping[str, FrozenJsonValue],
        effective_ns: int,
    ) -> None:
        """Apply only finished cancel/hibernation action reports."""

        states = payload.get("instantActionStates")
        if not isinstance(states, Sequence) or isinstance(states, (str, bytes)):
            return
        for state in states:
            if not isinstance(state, Mapping):
                continue
            action_id = state.get("actionId")
            if not isinstance(action_id, str) or state.get("actionStatus") != "FINISHED":
                continue
            key = self._pending_clear_actions.pop((robot, action_id), None)
            if key is not None:
                self._mark_terminal(
                    key, OrderOutcome.CANCELED_OR_CLEARED, effective_ns
                )

    def _apply_rejection_errors(
        self,
        robot: RobotIdentity,
        payload: Mapping[str, FrozenJsonValue],
        effective_ns: int,
    ) -> None:
        """Mark an observed order rejected only when error references name it."""

        raw_errors = payload.get("errors")
        if not isinstance(raw_errors, Sequence) or isinstance(
            raw_errors, (str, bytes)
        ):
            return
        for item in raw_errors:
            if not isinstance(item, Mapping):
                continue
            refs = item.get("errorReferences")
            if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)):
                continue
            order_ids = {
                str(ref.get("referenceValue"))
                for ref in refs
                if isinstance(ref, Mapping)
                and ref.get("referenceKey") == "orderId"
                and isinstance(ref.get("referenceValue"), str)
            }
            for order_id in order_ids:
                key = _OrderKey(robot.manufacturer, robot.serial_number, order_id)
                if key in self._orders:
                    self._mark_terminal(key, OrderOutcome.REJECTED, effective_ns)

    def _mark_terminal(
        self, key: _OrderKey, outcome: OrderOutcome, effective_ns: int
    ) -> None:
        """Set one terminal outcome once, preserving rejection precedence."""

        record = self._orders.get(key)
        if record is None:
            return
        if record.outcome is OrderOutcome.REJECTED:
            return
        if outcome is OrderOutcome.REJECTED or record.outcome is OrderOutcome.INDETERMINATE:
            record.outcome = outcome
            record.terminal_at_ns = effective_ns
        robot = RobotIdentity(key.manufacturer, key.serial_number)
        if self._active_order_by_robot.get(robot) == key:
            self._active_order_by_robot.pop(robot, None)

    def _taint_active_orders(self) -> None:
        """Prevent later facts from proving a lifecycle across a discontinuity."""

        for key in self._active_order_by_robot.values():
            record = self._orders.get(key)
            if record is not None and record.outcome is OrderOutcome.INDETERMINATE:
                record.crossed_discontinuity = True
        if self._active_order_by_robot:
            self._append_diagnostic(
                EventDiagnosticCode.ORDER_CROSSED_DISCONTINUITY
            )

    def _close_error(
        self, robot: RobotIdentity, identity: _ErrorIdentity, end_ns: int
    ) -> None:
        """Close one active error without creating a negative interval."""

        active = self._active_errors.get(robot, {}).pop(identity, None)
        if active is None:
            return
        bounded_end = max(active.start_ns, end_ns)
        if len(self._error_episodes) >= MAX_ERROR_EPISODES:
            self._partial = True
            self._append_diagnostic(EventDiagnosticCode.RESOURCE_LIMIT)
            return
        self._error_episodes.append(
            _ErrorEpisode(robot, identity, active.start_ns, bounded_end)
        )

    def _close_robot_errors(self, robot: RobotIdentity, end_ns: int) -> None:
        """Close every active error for one robot at a continuity boundary."""

        for identity in tuple(self._active_errors.get(robot, {})):
            self._close_error(robot, identity, end_ns)

    def _close_all_errors(self, end_ns: int) -> None:
        """Close every active error at a capture or collector boundary."""

        for robot in tuple(self._active_errors):
            self._close_robot_errors(robot, end_ns)

    def _finalize_robot_observation(self, end_ns: int) -> None:
        """Carry the last state sample only through the declared trust horizon."""

        for state in self._robot_observation.values():
            if (
                state.last_state_ns is not None
                and state.last_epoch == self._active_epoch
                and not state.hibernating
            ):
                state.observed_duration_ns += min(
                    max(0, end_ns - state.last_state_ns),
                    STATE_CARRY_FORWARD_NS,
                )

    def _window(self) -> EvaluationWindow | None:
        """Return the declared capture window when it is positive."""

        start = self._capture_start_ns
        end = self._capture_end_ns or self._maximum_time_ns
        if start is None or end is None or end <= start:
            return None
        return EvaluationWindow(start, end)

    def _coverage(self, window: EvaluationWindow) -> Coverage:
        """Return exact collector-session coverage or explicitly withhold it."""

        retained = self._coverage_gaps.retained_intervals(window)
        missing = tuple(
            MissingInterval(item.start_ns, item.end_ns, item.reason)
            for item in retained
        )
        missing_duration = self._coverage_gaps.exact_union_duration_ns(window)
        truncated = self._coverage_gaps.details_truncated
        if truncated:
            self._partial = True
            self._append_diagnostic(EventDiagnosticCode.INTERVAL_DETAILS_TRUNCATED)
        if missing_duration is None:
            self._partial = True
            self._append_diagnostic(EventDiagnosticCode.COVERAGE_DURATION_UNAVAILABLE)
            observed: int | None = None
        else:
            observed = window.duration_ns - missing_duration
        return Coverage(
            eligible_duration_ns=window.duration_ns,
            observed_duration_ns=observed,
            missing_intervals=missing,
            known_missing_interval_count=self._coverage_gaps.known_interval_count,
            missing_interval_details_truncated=truncated,
        )

    def _observed_orders_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
        coverage: Coverage,
    ) -> FunctionResult:
        """Return unique observed order/update identities without acceptance claims."""

        rows = [
            {
                "robot_identity": _key_robot(key).to_dict(),
                "orderId": key.order_id,
                "observed_order_update_ids": sorted(record.proposals),
                "first_observed_at_ns": record.first_observed_at_ns,
            }
            for key, record in self._ordered_records()
        ]
        if not rows:
            return self._not_computable(
                EventDiagnosticCode.NO_RELEVANT_OBSERVATION
            )
        return self._result(
            OBSERVED_ORDERS_FUNCTION_ID,
            ResultBasis.REPORTED,
            summary,
            window,
            coverage,
            {"orders": rows, "unique_order_count": len(rows)},
            "orders",
        )

    def _error_episodes_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
        coverage: Coverage,
    ) -> FunctionResult:
        """Return bounded persistent raw-error episodes and exact durations."""

        rows = [
            {
                "robot_identity": episode.robot.to_dict(),
                "errorType": episode.identity.error_type,
                "errorLevel": episode.identity.error_level,
                "errorReferences": [
                    {"referenceKey": key, "referenceValue": value}
                    for key, value in episode.identity.references
                ],
                "start_ns": episode.start_ns,
                "end_ns": episode.end_ns,
                "duration_ns": episode.end_ns - episode.start_ns,
            }
            for episode in sorted(
                self._error_episodes,
                key=lambda item: (
                    _subject_id(item.robot),
                    item.start_ns,
                    item.identity,
                ),
            )
        ]
        if not self._subjects:
            return self._not_computable(
                EventDiagnosticCode.NO_RELEVANT_OBSERVATION
            )
        return self._result(
            ACTIVE_ERROR_EPISODES_FUNCTION_ID,
            ResultBasis.INFERRED,
            summary,
            window,
            coverage,
            {"episodes": rows, "episode_count": len(rows)},
            "nanoseconds",
        )

    def _order_outcomes_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
        coverage: Coverage,
    ) -> FunctionResult:
        """Return conservative inferred outcomes for every observed order."""

        rows = [self._outcome_row(key, record) for key, record in self._ordered_records()]
        if not rows:
            return self._not_computable(
                EventDiagnosticCode.NO_RELEVANT_OBSERVATION
            )
        counts = {outcome.value: 0 for outcome in OrderOutcome}
        for row in rows:
            counts[str(row["outcome"])] += 1
        return self._result(
            PROTOCOL_ORDER_OUTCOMES_FUNCTION_ID,
            ResultBasis.INFERRED,
            summary,
            window,
            coverage,
            {"outcomes": rows, "counts": counts},
            "orders",
        )

    def _execution_duration_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
        coverage: Coverage,
    ) -> FunctionResult:
        """Return acceptance-to-inferred-finish durations only for defensible rows."""

        rows = []
        for key, record in self._ordered_records():
            if (
                record.outcome is not OrderOutcome.INFERRED_FINISHED
                or record.accepted_at_ns is None
                or record.terminal_at_ns is None
                or record.crossed_discontinuity
            ):
                continue
            rows.append(
                {
                    "robot_identity": _key_robot(key).to_dict(),
                    "orderId": key.order_id,
                    "accepted_at_ns": record.accepted_at_ns,
                    "inferred_finished_at_ns": record.terminal_at_ns,
                    "duration_ns": record.terminal_at_ns - record.accepted_at_ns,
                }
            )
        if not self._orders:
            return self._not_computable(
                EventDiagnosticCode.NO_RELEVANT_OBSERVATION
            )
        durations = [int(row["duration_ns"]) for row in rows]
        value = {
            "orders": rows,
            "included_order_count": len(rows),
            "excluded_order_count": len(self._orders) - len(rows),
            "minimum_duration_ns": min(durations) if durations else None,
            "maximum_duration_ns": max(durations) if durations else None,
            "mean_duration_ns": (
                sum(durations) / len(durations) if durations else None
            ),
        }
        return self._result(
            PROTOCOL_ORDER_EXECUTION_DURATION_FUNCTION_ID,
            ResultBasis.INFERRED,
            summary,
            window,
            coverage,
            value,
            "nanoseconds",
        )

    def _finished_rate_result(
        self,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
        coverage: Coverage,
    ) -> FunctionResult:
        """Return finished orders per eligible observed robot-hour."""

        finished = {
            key
            for key, record in self._orders.items()
            if record.outcome is OrderOutcome.INFERRED_FINISHED
            and not record.crossed_discontinuity
        }
        observed_ns = sum(
            state.observed_duration_ns for state in self._robot_observation.values()
        )
        if not self._subjects or observed_ns <= 0:
            return self._not_computable(
                EventDiagnosticCode.NO_RELEVANT_OBSERVATION
            )
        hours = observed_ns / 3_600_000_000_000
        value = len(finished) / hours
        return self._result(
            FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_FUNCTION_ID,
            ResultBasis.INFERRED,
            summary,
            window,
            coverage,
            value,
            "finished_orders/observed_robot_hour",
            numerator=len(finished),
            denominator={
                "observed_robot_time_ns": observed_ns,
                "observed_robot_hours": hours,
            },
        )

    def _result(
        self,
        function_id: str,
        basis: ResultBasis,
        summary: NormalizedCaptureSummary,
        window: EvaluationWindow,
        coverage: Coverage,
        value: object,
        unit: str,
        *,
        numerator: object = None,
        denominator: object = None,
    ) -> FunctionResult:
        """Build one schema-safe result with verified input references."""

        status = ResultStatus.PARTIAL if self._partial else ResultStatus.COMPUTED
        return FunctionResult(
            function_id=function_id,
            function_version=EVENT_FUNCTION_VERSION,
            status=status,
            basis=basis,
            scope=ResultScope(
                ScopeKind.OBSERVED_ROBOT_COHORT,
                tuple(sorted(self._subjects.values())),
            ),
            window=window,
            coverage=coverage,
            method_version=EVENT_FUNCTION_VERSION,
            value=value,
            unit=unit,
            numerator=numerator,
            denominator=denominator,
            input_references=self._input_references(summary.input_sha256),
            diagnostics=self._diagnostic_values(),
        )

    def _not_computable(self, reason: EventDiagnosticCode) -> FunctionResult:
        """Build a zero-coverage result when no defensible value exists."""

        self._append_diagnostic(reason)
        function_id, basis = _function_identity(self._kind)
        return FunctionResult(
            function_id=function_id,
            function_version=EVENT_FUNCTION_VERSION,
            status=ResultStatus.NOT_COMPUTABLE,
            basis=basis,
            scope=ResultScope(ScopeKind.SOURCE, (self._source_id,)),
            window=None,
            coverage=Coverage(0, 0),
            method_version=EVENT_FUNCTION_VERSION,
            diagnostics=self._diagnostic_values(),
        )

    def _ordered_records(self) -> tuple[tuple[_OrderKey, _OrderRecord], ...]:
        """Return order records in deterministic first-seen and identity order."""

        return tuple(
            sorted(
                self._orders.items(),
                key=lambda item: (
                    item[1].first_observed_at_ns,
                    item[0].manufacturer,
                    item[0].serial_number,
                    item[0].order_id,
                ),
            )
        )

    def _outcome_row(
        self, key: _OrderKey, record: _OrderRecord
    ) -> dict[str, object]:
        """Return one stable order-outcome row without hidden acceptance claims."""

        outcome = (
            OrderOutcome.INDETERMINATE
            if record.crossed_discontinuity
            else record.outcome
        )
        return {
            "robot_identity": _key_robot(key).to_dict(),
            "orderId": key.order_id,
            "accepted_order_update_ids": sorted(record.accepted_updates),
            "outcome": outcome.value,
        }

    def _append_reference(self, observation: NormalizedVdaObservation) -> None:
        """Retain one bounded portable message reference."""

        candidate = _ReferenceCandidate(
            observation.locator,
            observation.message_family.value,
            observation.topic,
            f"headerId:{observation.header_id}",
        )
        if candidate in self._reference_seen:
            return
        if len(self._reference_candidates) >= MAX_EVENT_INPUT_REFERENCES:
            self._partial = True
            self._append_diagnostic(EventDiagnosticCode.RESOURCE_LIMIT)
            return
        self._reference_seen.add(candidate)
        self._reference_candidates.append(candidate)

    def _input_references(self, input_sha256: str) -> tuple[InputReference, ...]:
        """Bind retained record identities to the verified capture digest."""

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

    def _append_diagnostic(
        self, code: EventDiagnosticCode, locator: str | None = None
    ) -> None:
        """Append one bounded unique symbolic diagnostic."""

        value = code.value if locator is None else f"{code.value}@{locator}"
        if value in self._diagnostic_seen:
            return
        if len(self._diagnostics) >= MAX_EVENT_DIAGNOSTICS:
            self._diagnostics_truncated = True
            return
        self._diagnostic_seen.add(value)
        self._diagnostics.append(value)

    def _diagnostic_values(self) -> tuple[str, ...]:
        """Return bounded diagnostics plus a stable truncation marker."""

        values = list(self._diagnostics)
        if self._diagnostics_truncated:
            values.append(EventDiagnosticCode.DIAGNOSTICS_TRUNCATED.value)
        return tuple(values)


def _function_identity(kind: EventFunctionKind) -> tuple[str, ResultBasis]:
    """Map a compiled event kind to its public function identity and basis."""

    return {
        EventFunctionKind.OBSERVED_ORDERS: (
            OBSERVED_ORDERS_FUNCTION_ID,
            ResultBasis.REPORTED,
        ),
        EventFunctionKind.ERROR_EPISODES: (
            ACTIVE_ERROR_EPISODES_FUNCTION_ID,
            ResultBasis.INFERRED,
        ),
        EventFunctionKind.ORDER_OUTCOMES: (
            PROTOCOL_ORDER_OUTCOMES_FUNCTION_ID,
            ResultBasis.INFERRED,
        ),
        EventFunctionKind.EXECUTION_DURATION: (
            PROTOCOL_ORDER_EXECUTION_DURATION_FUNCTION_ID,
            ResultBasis.INFERRED,
        ),
        EventFunctionKind.FINISHED_RATE: (
            FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_FUNCTION_ID,
            ResultBasis.INFERRED,
        ),
    }[kind]


def _subject_id(robot: RobotIdentity) -> str:
    """Build the explicit cohort subject label from exact VDA identity fields."""

    return f"{robot.manufacturer}/{robot.serial_number}"


def _key_robot(key: _OrderKey) -> RobotIdentity:
    """Reconstruct an immutable robot identity from an order key."""

    return RobotIdentity(key.manufacturer, key.serial_number)


def _final_released_node(
    nodes: FrozenJsonValue | None,
) -> tuple[str | None, int | None]:
    """Return the highest-sequence released node with a non-empty ID."""

    if not isinstance(nodes, Sequence) or isinstance(nodes, (str, bytes)):
        return None, None
    candidates: list[tuple[int, str]] = []
    for node in nodes:
        if not isinstance(node, Mapping) or node.get("released") is not True:
            continue
        node_id = node.get("nodeId")
        sequence = node.get("sequenceId")
        if (
            isinstance(node_id, str)
            and node_id
            and isinstance(sequence, int)
            and not isinstance(sequence, bool)
        ):
            candidates.append((sequence, node_id))
    if not candidates:
        return None, None
    sequence, node_id = max(candidates)
    return node_id, sequence


def _state_proves_terminal(
    payload: Mapping[str, FrozenJsonValue], proposal: _OrderProposal
) -> bool:
    """Apply the documented conservative terminal inference predicate."""

    if proposal.final_node_id is None or proposal.final_node_sequence_id is None:
        return False
    if payload.get("lastNodeId") != proposal.final_node_id:
        return False
    if payload.get("lastNodeSequenceId") != proposal.final_node_sequence_id:
        return False
    for field in ("nodeStates", "edgeStates"):
        value = payload.get(field)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)) or value:
            return False
    for field in ("actionStates", "instantActionStates"):
        value = payload.get(field)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return False
        for action in value:
            if not isinstance(action, Mapping) or action.get("actionStatus") not in {
                "FINISHED",
                "FAILED",
            }:
                return False
    return True


def _action_parameter(action: Mapping[str, object], key: str) -> str | None:
    """Read one exact string action parameter without inferring defaults."""

    parameters = action.get("actionParameters")
    if not isinstance(parameters, Sequence) or isinstance(parameters, (str, bytes)):
        return None
    for parameter in parameters:
        if (
            isinstance(parameter, Mapping)
            and parameter.get("key") == key
            and isinstance(parameter.get("value"), str)
        ):
            return str(parameter["value"])
    return None


def _error_identity(value: object) -> _ErrorIdentity | None:
    """Canonicalize one schema-valid raw error into an episode identity."""

    if not isinstance(value, Mapping):
        return None
    error_type = value.get("errorType")
    error_level = value.get("errorLevel")
    if not isinstance(error_type, str) or not isinstance(error_level, str):
        return None
    references: list[tuple[str, str]] = []
    raw_references = value.get("errorReferences")
    if isinstance(raw_references, Sequence) and not isinstance(
        raw_references, (str, bytes)
    ):
        for reference in raw_references:
            if not isinstance(reference, Mapping):
                continue
            key = reference.get("referenceKey")
            item = reference.get("referenceValue")
            if isinstance(key, str) and isinstance(item, str):
                references.append((key, item))
    return _ErrorIdentity(error_type, error_level, tuple(sorted(set(references))))
