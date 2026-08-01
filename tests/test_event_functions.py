import hashlib
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from mekai_open.contracts import ResultStatus
from mekai_open.event_functions import (
    ACTIVE_ERROR_EPISODES_QUALIFIED_ID,
    FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID,
    OBSERVED_ORDERS_QUALIFIED_ID,
    PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID,
    PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID,
    CohortEventExecutor,
)
from mekai_open.function_registry import get_function_executor
from mekai_open.observations import (
    CaptureBoundaryKind,
    CaptureBoundaryObservation,
    CollectorSessionObservation,
    NormalizedCaptureSummary,
    NormalizedVdaObservation,
    RobotIdentity,
    SessionBoundaryKind,
)
from mekai_open.vda_schemas import VdaMessageFamily


ROOT = Path(__file__).parents[1]
WIRE = ROOT / "fixtures" / "vda5050" / "order_lifecycle_wire.json"
TRUTH = ROOT / "fixtures" / "truth"
RESULT_SCHEMA = ROOT / "schemas" / "function-result-0.1.schema.json"
SOURCE_ID = "order-lifecycle"
INPUT_SHA256 = "b" * 64
END_NS = 62_000_000_000


def _wire_observations():
    wire = json.loads(WIRE.read_text(encoding="utf-8"))
    for index, record in enumerate(wire["records"], start=2):
        payload = record["message"]
        raw = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        family = VdaMessageFamily(record["message_family"])
        robot = RobotIdentity(payload["manufacturer"], payload["serialNumber"])
        yield NormalizedVdaObservation(
            source_id=SOURCE_ID,
            locator=f"wire:{index}",
            observation_time_ns=record["observation_time_ns"],
            continuity_epoch=1,
            message_family=family,
            topic=(
                f"synthetic/{robot.serial_number}/{family.value}"
            ),
            robot_identity=robot,
            header_id=payload["headerId"],
            source_timestamp=payload["timestamp"],
            retained=False,
            producer_duplicate=False,
            payload_sha256=hashlib.sha256(raw).hexdigest(),
            validated_payload=payload,
        )


def _run(qualified_id: str):
    executor = get_function_executor(qualified_id, source_id=SOURCE_ID)
    assert isinstance(executor, CohortEventExecutor)
    executor.consume(
        CaptureBoundaryObservation(
            source_id=SOURCE_ID,
            locator="wire:start",
            observation_time_ns=0,
            sequence=0,
            kind=CaptureBoundaryKind.START,
            declared_complete=None,
        )
    )
    executor.consume(
        CollectorSessionObservation(
            source_id=SOURCE_ID,
            locator="wire:session-start",
            observation_time_ns=0,
            sequence=1,
            kind=SessionBoundaryKind.START,
            producer_session_id="wire-session",
            continuity_epoch=1,
        )
    )
    for observation in _wire_observations():
        executor.consume(observation)
    executor.consume(
        CollectorSessionObservation(
            source_id=SOURCE_ID,
            locator="wire:session-end",
            observation_time_ns=END_NS,
            sequence=27,
            kind=SessionBoundaryKind.END,
            producer_session_id="wire-session",
            continuity_epoch=1,
        )
    )
    executor.consume(
        CaptureBoundaryObservation(
            source_id=SOURCE_ID,
            locator="wire:end",
            observation_time_ns=END_NS,
            sequence=28,
            kind=CaptureBoundaryKind.END,
            declared_complete=True,
        )
    )
    return executor.finish(
        NormalizedCaptureSummary(
            source_id=SOURCE_ID,
            input_sha256=INPUT_SHA256,
            physical_record_count=29,
            accepted_record_count=29,
            declared_complete=True,
            structurally_compromised=False,
            verified_unchanged=True,
            complete=True,
            diagnostic_codes=(),
        )
    )


class CohortEventTruthTests(unittest.TestCase):
    def test_order_outcome_truth_runs_through_executor(self) -> None:
        expected = json.loads(
            (TRUTH / "protocol_order_outcomes.json").read_text(encoding="utf-8")
        )["expected"]
        result = _run(PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID)
        actual = result.to_dict()
        self.assertEqual(actual["status"], expected["status"])
        self.assertEqual(actual["basis"], expected["basis"])
        self.assertEqual(actual["scope"], expected["scope"])
        self.assertEqual(actual["value"]["outcomes"], expected["outcomes"])
        self.assertEqual(actual["value"]["counts"], expected["counts"])

    def test_observed_orders_do_not_claim_acceptance(self) -> None:
        result = _run(OBSERVED_ORDERS_QUALIFIED_ID)
        value = result.to_dict()["value"]
        self.assertEqual(value["unique_order_count"], 7)
        self.assertEqual(
            next(
                row["observed_order_update_ids"]
                for row in value["orders"]
                if row["orderId"] == "updated-order"
            ),
            [0, 1],
        )
        serialized = json.dumps(value)
        self.assertNotIn("accepted_order_update_ids", serialized)
        self.assertNotIn("INFERRED_FINISHED", serialized)

    def test_execution_duration_includes_only_inferred_finished_orders(self) -> None:
        result = _run(PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID)
        value = result.to_dict()["value"]
        self.assertEqual(value["included_order_count"], 3)
        self.assertEqual(value["excluded_order_count"], 4)
        self.assertEqual(
            sorted(row["duration_ns"] for row in value["orders"]),
            [1_000_000_000, 1_000_000_000, 3_000_000_000],
        )

    def test_error_episode_preserves_raw_identity_and_duration(self) -> None:
        result = _run(ACTIVE_ERROR_EPISODES_QUALIFIED_ID)
        value = result.to_dict()["value"]
        self.assertEqual(value["episode_count"], 1)
        episode = value["episodes"][0]
        self.assertEqual(episode["errorType"], "INVALID_ORDER_ACTION")
        self.assertEqual(episode["errorLevel"], "WARNING")
        self.assertEqual(episode["duration_ns"], 1_000_000_000)

    def test_rate_is_explicitly_per_observed_robot_hour(self) -> None:
        result = _run(FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID)
        actual = result.to_dict()
        self.assertGreater(actual["denominator"]["observed_robot_time_ns"], 0)
        self.assertEqual(actual["numerator"], 3)
        self.assertEqual(actual["unit"], "finished_orders/observed_robot_hour")
        self.assertNotIn("throughput", json.dumps(actual).lower())

    def test_all_event_results_validate_and_are_deterministic(self) -> None:
        validator = Draft202012Validator(
            json.loads(RESULT_SCHEMA.read_text(encoding="utf-8"))
        )
        for qualified_id in (
            OBSERVED_ORDERS_QUALIFIED_ID,
            ACTIVE_ERROR_EPISODES_QUALIFIED_ID,
            PROTOCOL_ORDER_OUTCOMES_QUALIFIED_ID,
            PROTOCOL_ORDER_EXECUTION_DURATION_QUALIFIED_ID,
            FINISHED_ORDERS_PER_OBSERVED_ROBOT_HOUR_QUALIFIED_ID,
        ):
            with self.subTest(qualified_id=qualified_id):
                first = _run(qualified_id)
                second = _run(qualified_id)
                self.assertEqual(first.to_json(), second.to_json())
                self.assertEqual(
                    list(validator.iter_errors(first.to_dict())), []
                )
                self.assertIn(
                    first.status, {ResultStatus.COMPUTED, ResultStatus.PARTIAL}
                )


if __name__ == "__main__":
    unittest.main()
