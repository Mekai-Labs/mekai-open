"""Built-in function specifications."""

from __future__ import annotations

from collections.abc import Callable
from types import MappingProxyType
from typing import Mapping

from .contracts import FieldRequirement, FunctionSpec, ResultBasis
from .event_functions import (
    ACTIVE_ERROR_EPISODES_FUNCTION_ID,
    ACTIVE_ERROR_EPISODES_QUALIFIED_ID,
    FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_FUNCTION_ID,
    FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID,
    OBSERVED_ORDERS_FUNCTION_ID,
    OBSERVED_ORDERS_QUALIFIED_ID,
    PROTOCOL_ORDER_EXECUTION_DURATION_FUNCTION_ID,
    PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID,
    PROTOCOL_ORDER_OUTCOMES_FUNCTION_ID,
    PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID,
    CohortEventExecutor,
    EventFunctionKind,
)
from .observations import RobotTarget
from .recorded_functions import RecordedFunctionExecutor
from .reported_durations import (
    REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID,
    REPORTED_CHARGING_DURATION_QUALIFIED_ID,
    REPORTED_CONNECTION_STATE_DURATION_FUNCTION_ID,
    REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID,
    REPORTED_DRIVING_DURATION_FUNCTION_ID,
    REPORTED_DRIVING_DURATION_QUALIFIED_ID,
    REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID,
    REPORTED_PAUSED_DURATION_QUALIFIED_ID,
    REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID,
    ReportedBatteryStateOfChargeExecutor,
    ReportedConnectionStateDurationExecutor,
    ReportedDrivingDurationExecutor,
    ReportedStateDurationExecutor,
    ReportedStateDurationKind,
)
from .state_stream_health import (
    STATE_STREAM_HEALTH_FUNCTION_ID,
    STATE_STREAM_HEALTH_QUALIFIED_ID,
    StateStreamHealthExecutor,
)

_RESULT_SCHEMA = "mekai.function_result/0.1"


def _reported(
    function_id: str,
    families: tuple[str, ...],
    fields: tuple[FieldRequirement, ...],
    method: str,
    missing: tuple[str, ...],
    fixtures: tuple[str, ...],
) -> FunctionSpec:
    """Construct a specification whose result basis is directly reported."""

    return FunctionSpec(
        function_id=function_id,
        version="0.1.0",
        required_message_families=families,
        required_fields=fields,
        method=method,
        basis=ResultBasis.REPORTED,
        missing_data_requirements=missing,
        result_schema=_RESULT_SCHEMA,
        fixture_ids=fixtures,
    )


def _inferred(
    function_id: str,
    families: tuple[str, ...],
    fields: tuple[FieldRequirement, ...],
    method: str,
    missing: tuple[str, ...],
    fixtures: tuple[str, ...],
) -> FunctionSpec:
    """Construct a specification whose result basis is an inference."""

    return FunctionSpec(
        function_id=function_id,
        version="0.1.0",
        required_message_families=families,
        required_fields=fields,
        method=method,
        basis=ResultBasis.INFERRED,
        missing_data_requirements=missing,
        result_schema=_RESULT_SCHEMA,
        fixture_ids=fixtures,
    )


BUILTIN_FUNCTIONS: tuple[FunctionSpec, ...] = (
    _reported(
        REPORTED_CONNECTION_STATE_DURATION_FUNCTION_ID,
        ("connection",),
        (
            FieldRequirement(
                "connection",
                (
                    "connectionState",
                    "headerId",
                    "manufacturer",
                    "serialNumber",
                    "timestamp",
                ),
            ),
        ),
        "Integrate trustworthy exact-target connectionState transitions from "
        "capture receive time until the next transition, collector-session "
        "boundary, relevant discontinuity, or capture end.",
        (
            "Session boundaries and collector drops create UNKNOWN.",
            "Connection state has no 30-second expiry.",
            "Confirmed HIBERNATING remains a reported connection state; it is "
            "not UNKNOWN.",
            "Retained connection messages may establish state from capture "
            "receipt time.",
            "Conflicting, regressed, or out-of-uint32 headers cannot establish "
            "a transition.",
        ),
        ("truth.connection_session_boundary",),
    ),
    _reported(
        REPORTED_DRIVING_DURATION_FUNCTION_ID,
        ("connection", "state"),
        (
            FieldRequirement(
                "connection",
                (
                    "connectionState",
                    "headerId",
                    "manufacturer",
                    "serialNumber",
                    "timestamp",
                ),
            ),
            FieldRequirement(
                "state",
                (
                    "driving",
                    "headerId",
                    "manufacturer",
                    "serialNumber",
                    "timestamp",
                ),
            ),
        ),
        "Integrate trustworthy exact-target reported driving from capture "
        "receive time with a 30-second carry-forward.",
        (
            "Time beyond carry-forward and collector gaps is missing.",
            "Confirmed HIBERNATING intervals are excluded from eligible "
            "state-derived duration.",
            "Retained state messages cannot establish or refresh driving state.",
            "Conflicting, regressed, or out-of-uint32 headers cannot establish "
            "or refresh driving state.",
        ),
        ("truth.state_gap_missingness",),
    ),
    _reported(
        "vda.reported_operating_mode_duration",
        ("state",),
        (FieldRequirement("state", ("operatingMode",)),),
        "Integrate reported operatingMode with a 30-second carry-forward.",
        (
            "Time beyond carry-forward and collector gaps is missing.",
            "Confirmed HIBERNATING intervals are excluded from eligible "
            "state-derived duration.",
        ),
        ("truth.operating_mode_duration",),
    ),
    _reported(
        "vda.reported_paused_duration",
        ("state",),
        (FieldRequirement("state", ("paused",)),),
        "Integrate optional reported paused state with a 30-second "
        "carry-forward.",
        (
            "Return NOT_COMPUTABLE when paused is absent throughout.",
            "Confirmed HIBERNATING intervals are excluded from eligible "
            "state-derived duration.",
        ),
        ("truth.paused_duration",),
    ),
    _reported(
        "vda.reported_charging_duration",
        ("state",),
        (FieldRequirement("state", ("powerSupply.charging",)),),
        "Integrate reported charging with a 30-second carry-forward.",
        (
            "Time beyond carry-forward and collector gaps is missing.",
            "Confirmed HIBERNATING intervals are excluded from eligible "
            "state-derived duration.",
        ),
        ("truth.charging_duration",),
    ),
    _reported(
        "vda.reported_battery_state_of_charge",
        ("state",),
        (FieldRequirement("state", ("powerSupply.stateOfCharge",)),),
        "Report first, minimum, and last observed state of charge without "
        "interpolating across missing intervals.",
        (
            "Require at least one valid state-of-charge observation.",
            "Confirmed HIBERNATING silence is expected and is not a missing "
            "state interval.",
        ),
        ("truth.battery_state_of_charge",),
    ),
    _reported(
        "vda.reported_safety_state_duration",
        ("state",),
        (
            FieldRequirement(
                "state",
                ("safetyState.activeEmergencyStop", "safetyState.fieldViolation"),
            ),
        ),
        "Integrate the two reported safetyState fields descriptively.",
        (
            "Never interpret reported fields as a safety or conformity finding.",
            "Confirmed HIBERNATING intervals are excluded from eligible "
            "state-derived duration.",
        ),
        ("truth.safety_state_duration",),
    ),
    _reported(
        STATE_STREAM_HEALTH_FUNCTION_ID,
        ("connection", "state"),
        (
            FieldRequirement(
                "connection",
                (
                    "connectionState",
                    "headerId",
                    "manufacturer",
                    "serialNumber",
                    "timestamp",
                ),
            ),
            FieldRequirement(
                "state",
                ("headerId", "manufacturer", "serialNumber", "timestamp"),
            ),
        ),
        "Report capture/source counts and independently keyed state-stream "
        "cadence, uint32 state/connection header handling, retained messages, "
        "duplicates, drops, collector-session boundaries, and silence from "
        "capture receive time.",
        (
            "Health remains reportable when another function is not computable.",
            "Report confirmed HIBERNATING silence as expected; silence without "
            "confirmation remains a possible source-health gap.",
            "Capture-rejected and VDA-invalid messages remain diagnostic facts "
            "and cannot create state transitions.",
            "Known time outside accepted collector sessions lowers source "
            "coverage. When interval detail is truncated, exact duration remains "
            "available only for forward-ordered in-window gaps; otherwise the "
            "duration and ratio are explicitly unavailable.",
            "Explicit drops receive no fabricated duration.",
            "Out-of-range connection headers remain counted facts but cannot "
            "establish or change connection or hibernation state.",
        ),
        ("truth.state_stream_health",),
    ),
    _reported(
        OBSERVED_ORDERS_FUNCTION_ID,
        ("order",),
        (FieldRequirement("order", ("orderId", "orderUpdateId")),),
        "List unique observed order identities without implying acceptance or finish.",
        ("Observation alone is not a terminal outcome.",),
        ("truth.observed_orders",),
    ),
    _inferred(
        ACTIVE_ERROR_EPISODES_FUNCTION_ID,
        ("state",),
        (FieldRequirement("state", ("errors",)),),
        "Build episodes from persistent raw VDA error identities and levels.",
        (
            "Gaps split episodes and remain visible.",
            "Confirmed HIBERNATING silence is expected and excluded from "
            "eligible state-derived time.",
        ),
        ("truth.active_error_episodes",),
    ),
    _inferred(
        PROTOCOL_ORDER_OUTCOMES_FUNCTION_ID,
        ("order", "instantActions", "state"),
        (
            FieldRequirement("order", ("orderId", "orderUpdateId", "nodes", "edges")),
            FieldRequirement("instantActions", ("actions",)),
            FieldRequirement(
                "state",
                (
                    "orderId",
                    "orderUpdateId",
                    "lastNodeId",
                    "lastNodeSequenceId",
                    "nodeStates",
                    "edgeStates",
                    "actionStates",
                    "instantActionStates",
                    "operatingMode",
                    "errors",
                ),
            ),
        ),
        "Infer accepted terminal outcomes using order echo, named final-node "
        "progress, terminal actions, and cancel/clear exclusions. VDA has no "
        "explicit order-complete event.",
        (
            "Idle or empty node/edge arrays alone never prove finish.",
            "Ignore lastNodeSequenceId whenever lastNodeId is empty.",
            "Entering hibernation clears the active order and never proves finish.",
        ),
        ("truth.protocol_order_outcomes",),
    ),
    _inferred(
        PROTOCOL_ORDER_EXECUTION_DURATION_FUNCTION_ID,
        ("order", "instantActions", "state"),
        (
            FieldRequirement(
                "order", ("orderId", "orderUpdateId", "nodes", "edges")
            ),
            FieldRequirement("instantActions", ("actions",)),
            FieldRequirement(
                "state",
                (
                    "orderId",
                    "orderUpdateId",
                    "lastNodeId",
                    "lastNodeSequenceId",
                    "nodeStates",
                    "edgeStates",
                    "actionStates",
                    "instantActionStates",
                    "operatingMode",
                    "errors",
                ),
            ),
        ),
        "Measure observed acceptance-to-defensible inferred-terminal duration; "
        "VDA has no explicit order-complete event.",
        (
            "Exclude truncated, reused, conflicting, or gap-spanning lifecycles.",
            "Ignore lastNodeSequenceId whenever lastNodeId is empty.",
            "Entering hibernation clears the active order and never proves finish.",
        ),
        ("truth.protocol_order_execution_duration",),
    ),
    _inferred(
        FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_FUNCTION_ID,
        ("order", "instantActions", "state"),
        (
            FieldRequirement(
                "order", ("orderId", "orderUpdateId", "nodes", "edges")
            ),
            FieldRequirement("instantActions", ("actions",)),
            FieldRequirement(
                "state",
                (
                    "orderId",
                    "orderUpdateId",
                    "lastNodeId",
                    "lastNodeSequenceId",
                    "nodeStates",
                    "edgeStates",
                    "actionStates",
                    "instantActionStates",
                    "operatingMode",
                    "errors",
                ),
            ),
        ),
        "Count each accepted inferred-finished robot/order identity once and "
        "divide by eligible observed robot-hours.",
        (
            "Exclude missing/session/drop intervals from observed robot-hours.",
            "Exclude confirmed HIBERNATING intervals from eligible observed "
            "robot-hours.",
            "Ignore lastNodeSequenceId whenever lastNodeId is empty.",
            "Entering hibernation clears the active order and never proves finish.",
            "Never label this site, business, material, fleet, or universal "
            "throughput.",
        ),
        ("truth.finished_orders_per_observed_robot_hour",),
    ),
)

_BY_QUALIFIED_ID = {item.qualified_id: item for item in BUILTIN_FUNCTIONS}
if len(_BY_QUALIFIED_ID) != len(BUILTIN_FUNCTIONS):
    raise RuntimeError("duplicate built-in function qualified ID")

type _ExecutorFactory = Callable[
    [str, RobotTarget | None], RecordedFunctionExecutor
]


def _source_health_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the source-scoped health executor without a robot target."""

    if robot_target is not None:
        raise ValueError("source-scoped executor does not accept a robot target")
    return StateStreamHealthExecutor(source_id)


def _connection_duration_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the connection-duration executor for one explicit robot target."""

    if robot_target is None:
        raise ValueError("robot-scoped executor requires a robot target")
    return ReportedConnectionStateDurationExecutor(source_id, robot_target)


def _driving_duration_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the driving-duration executor for one explicit robot target."""

    if robot_target is None:
        raise ValueError("robot-scoped executor requires a robot target")
    return ReportedDrivingDurationExecutor(source_id, robot_target)


def _state_duration_executor(
    source_id: str,
    robot_target: RobotTarget | None,
    kind: ReportedStateDurationKind,
) -> RecordedFunctionExecutor:
    """Create one declared state-duration executor for an explicit robot."""

    if robot_target is None:
        raise ValueError("robot-scoped executor requires a robot target")
    return ReportedStateDurationExecutor(source_id, robot_target, kind)


def _operating_mode_duration_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the reported operating-mode duration executor."""

    return _state_duration_executor(
        source_id, robot_target, ReportedStateDurationKind.OPERATING_MODE
    )


def _paused_duration_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the optional reported paused-duration executor."""

    return _state_duration_executor(
        source_id, robot_target, ReportedStateDurationKind.PAUSED
    )


def _charging_duration_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the reported charging-duration executor."""

    return _state_duration_executor(
        source_id, robot_target, ReportedStateDurationKind.CHARGING
    )


def _safety_state_duration_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the descriptive reported safety-state duration executor."""

    return _state_duration_executor(
        source_id, robot_target, ReportedStateDurationKind.SAFETY_STATE
    )


def _battery_state_of_charge_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the reported battery state-of-charge executor."""

    if robot_target is None:
        raise ValueError("robot-scoped executor requires a robot target")
    return ReportedBatteryStateOfChargeExecutor(source_id, robot_target)


def _cohort_event_executor(
    source_id: str,
    robot_target: RobotTarget | None,
    kind: EventFunctionKind,
) -> RecordedFunctionExecutor:
    """Create one cohort event executor without a robot-target filter."""

    if robot_target is not None:
        raise ValueError("cohort-scoped executor does not accept a robot target")
    return CohortEventExecutor(source_id, kind)


def _observed_orders_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the observed-order inventory executor."""

    return _cohort_event_executor(
        source_id, robot_target, EventFunctionKind.OBSERVED_ORDERS
    )


def _active_error_episodes_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the inferred active-error episode executor."""

    return _cohort_event_executor(
        source_id, robot_target, EventFunctionKind.ERROR_EPISODES
    )


def _order_outcomes_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the inferred protocol order-outcome executor."""

    return _cohort_event_executor(
        source_id, robot_target, EventFunctionKind.ORDER_OUTCOMES
    )


def _execution_duration_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the inferred order execution-duration executor."""

    return _cohort_event_executor(
        source_id, robot_target, EventFunctionKind.EXECUTION_DURATION
    )


def _finished_rate_executor(
    source_id: str, robot_target: RobotTarget | None
) -> RecordedFunctionExecutor:
    """Create the inferred finished-orders per observed robot-hour executor."""

    return _cohort_event_executor(
        source_id, robot_target, EventFunctionKind.FINISHED_RATE
    )


_EXECUTOR_FACTORIES: Mapping[str, _ExecutorFactory] = MappingProxyType(
    {
        STATE_STREAM_HEALTH_QUALIFIED_ID: _source_health_executor,
        REPORTED_CONNECTION_STATE_DURATION_QUALIFIED_ID: (
            _connection_duration_executor
        ),
        REPORTED_DRIVING_DURATION_QUALIFIED_ID: _driving_duration_executor,
        REPORTED_OPERATING_MODE_DURATION_QUALIFIED_ID: (
            _operating_mode_duration_executor
        ),
        REPORTED_PAUSED_DURATION_QUALIFIED_ID: _paused_duration_executor,
        REPORTED_CHARGING_DURATION_QUALIFIED_ID: _charging_duration_executor,
        REPORTED_BATTERY_STATE_OF_CHARGE_QUALIFIED_ID: (
            _battery_state_of_charge_executor
        ),
        REPORTED_SAFETY_STATE_DURATION_QUALIFIED_ID: (
            _safety_state_duration_executor
        ),
        OBSERVED_ORDERS_QUALIFIED_ID: _observed_orders_executor,
        ACTIVE_ERROR_EPISODES_QUALIFIED_ID: _active_error_episodes_executor,
        PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID: _order_outcomes_executor,
        PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID: (
            _execution_duration_executor
        ),
        FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID: (
            _finished_rate_executor
        ),
    }
)


def list_function_specs() -> tuple[FunctionSpec, ...]:
    """Return every declared built-in function specification in stable order."""

    return BUILTIN_FUNCTIONS


def get_function_spec(qualified_id: str) -> FunctionSpec:
    """Return one specification or raise ``KeyError`` for an unknown ID."""

    try:
        return _BY_QUALIFIED_ID[qualified_id]
    except KeyError as exc:
        raise KeyError(f"unknown built-in function: {qualified_id}") from exc


def list_executable_function_ids() -> tuple[str, ...]:
    """Return qualified IDs with statically bound first-party executors."""

    return tuple(sorted(_EXECUTOR_FACTORIES))


def get_function_executor(
    qualified_id: str,
    *,
    source_id: str,
    robot_target: RobotTarget | None = None,
) -> RecordedFunctionExecutor:
    """Create one statically bound executor or fail closed when unavailable."""

    try:
        factory = _EXECUTOR_FACTORIES[qualified_id]
    except KeyError as exc:
        raise KeyError(
            f"no compiled executor for built-in function: {qualified_id}"
        ) from exc
    return factory(source_id, robot_target)
