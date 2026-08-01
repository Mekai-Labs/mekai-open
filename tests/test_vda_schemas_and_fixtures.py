import json
import re
import unittest
from pathlib import Path

from mekai_open.vda_schemas import (
    assert_vendored_schemas,
    load_schema_manifest,
)


ROOT = Path(__file__).parents[1]
VENDOR_ROOT = ROOT / "src" / "mekai_open" / "_vendor" / "vda5050"
WIRE_FIXTURE = ROOT / "fixtures" / "vda5050" / "order_lifecycle_wire.json"


class VdaSchemaFixtureTests(unittest.TestCase):
    def test_vendored_vda_files_and_json(self) -> None:
        assert_vendored_schemas()
        manifest = load_schema_manifest()
        self.assertEqual(manifest["vda_version"], "3.0.0")
        self.assertEqual(manifest["upstream_release"]["tag"], "3.0.0")
        self.assertIsNotNone(
            re.fullmatch(
                r"[0-9a-f]{40}",
                manifest["upstream_schema_source_commit"],
            )
        )
        self.assertEqual(
            set(manifest["schemas"]),
            {
                "connection.schema",
                "instantActions.schema",
                "order.schema",
                "state.schema",
            },
        )

    def test_mekai_owned_schemas_are_json_with_unique_ids(self) -> None:
        ids: set[str] = set()
        paths = sorted((ROOT / "schemas").glob("*.json"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.name):
                content = json.loads(path.read_text(encoding="utf-8"))
                self.assertIn("$schema", content)
                self.assertIn("$id", content)
                self.assertNotIn(content["$id"], ids)
                ids.add(content["$id"])

    def test_configuration_schema_is_implemented_and_exact(self) -> None:
        content = json.loads(
            (ROOT / "schemas" / "config-0.1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        wording = f'{content["title"]} {content["$comment"]}'.lower()
        self.assertIn("implemented", wording)
        self.assertNotIn("design draft", wording)
        self.assertNotIn("unimplemented", wording)
        self.assertEqual(
            set(content["required"]), {"schema", "source_id", "robots", "limits"}
        )

    def test_capture_schema_is_implemented_but_not_publicly_stable(self) -> None:
        content = json.loads(
            (ROOT / "schemas" / "capture-record-0.1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        wording = f'{content["title"]} {content["$comment"]}'.lower()
        self.assertNotIn("unimplemented", wording)
        self.assertNotIn("design draft", wording)
        self.assertIn("implemented", wording)
        self.assertIn("not yet a stable public contract", wording)

    def test_truth_manifests_are_synthetic_and_unique(self) -> None:
        fixture_ids: set[str] = set()
        paths = sorted((ROOT / "fixtures" / "truth").glob("*.json"))
        self.assertTrue(paths)
        for path in paths:
            with self.subTest(path=path.name):
                content = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(content["schema"], "mekai.truth_manifest/0.1")
                self.assertIs(content["synthetic"], True)
                self.assertTrue(content["reviewer_arithmetic"])
                self.assertNotIn(content["fixture_id"], fixture_ids)
                fixture_ids.add(content["fixture_id"])

    def test_connection_truth_includes_nonzero_hibernation(self) -> None:
        truth = self._truth("connection_session_boundary")
        value = truth["expected"]["value_seconds"]
        self.assertEqual(value["ONLINE"], 60)
        self.assertEqual(value["OFFLINE"], 40)
        self.assertEqual(value["HIBERNATING"], 30)
        self.assertEqual(value["CONNECTION_BROKEN"], 10)
        self.assertEqual(value["UNKNOWN"], 10)
        self.assertEqual(sum(value.values()), 150)
        self.assertEqual(truth["expected"]["observed_seconds"], 140)

        expected_silence = truth["expected"][
            "expected_state_silence_intervals"
        ]
        self.assertEqual(expected_silence[0]["reason"], "CONFIRMED_HIBERNATION")
        self.assertGreater(
            expected_silence[0]["end"] - expected_silence[0]["start"], 0
        )

    def test_connection_truth_uses_official_vda_states(self) -> None:
        schema = self._vda_schema("connection")
        official = set(schema["properties"]["connectionState"]["enum"])
        truth = self._truth("connection_session_boundary")
        reported = set(truth["expected"]["value_seconds"]) - {"UNKNOWN"}
        self.assertEqual(reported, official)

    def test_state_truth_excludes_hibernation_but_keeps_unknown_missing(self) -> None:
        truth = self._truth("state_gap_missingness")
        expected = truth["expected"]
        value = expected["value_seconds"]
        self.assertEqual(sum(value.values()), expected["eligible_seconds"])
        self.assertEqual(expected["eligible_seconds"], 90)
        self.assertEqual(expected["observed_seconds"], 80)
        self.assertEqual(value["UNKNOWN"], 10)
        self.assertEqual(
            expected["coverage_ratio"],
            expected["observed_seconds"] / expected["eligible_seconds"],
        )
        self.assertEqual(
            expected["excluded_intervals"],
            [{"start": 50, "end": 80, "reason": "CONFIRMED_HIBERNATION"}],
        )
        self.assertEqual(
            expected["missing_intervals"],
            [
                {
                    "start": 110,
                    "end": 120,
                    "reason": "STATE_CARRY_FORWARD_EXPIRED",
                }
            ],
        )

    def test_lifecycle_wire_messages_have_official_required_fields(self) -> None:
        wire = self._wire()
        self.assertIs(wire["synthetic"], True)
        for record in wire["records"]:
            family = record["message_family"]
            message = record["message"]
            with self.subTest(case=record["case_id"], family=family):
                schema = self._vda_schema(family)
                self.assertLessEqual(set(schema["required"]), set(message))
                self.assertEqual(message["version"], "3.0.0")
                self.assertGreaterEqual(record["observation_time_ns"], 0)
                self._assert_nested_required_fields(family, message, schema)

    def test_lifecycle_wire_cases_cover_adversarial_boundaries(self) -> None:
        records = self._wire()["records"]
        self.assertEqual(
            {record["case_id"] for record in records},
            {
                "normal_progression",
                "same_order_id_other_robot",
                "empty_last_node",
                "order_update",
                "cancel_order",
                "hibernate_clear",
                "rejected_order",
            },
        )

        normal_states = self._case_messages("normal_progression", "state")
        self.assertTrue(normal_states[0]["nodeStates"])
        self.assertTrue(normal_states[0]["edgeStates"])
        self.assertEqual(normal_states[1]["lastNodeId"], "N1")
        self.assertEqual(normal_states[1]["nodeStates"], [])
        self.assertEqual(normal_states[1]["edgeStates"], [])
        self.assertEqual(normal_states[1], normal_states[2])

        empty_state = self._case_messages("empty_last_node", "state")[0]
        self.assertEqual(empty_state["lastNodeId"], "")
        self.assertEqual(empty_state["lastNodeSequenceId"], 999)
        empty_outcome = self._expected_outcome(
            "FixtureVendor", "R1", "empty-last-node"
        )
        self.assertEqual(empty_outcome["outcome"], "INDETERMINATE")

        update_orders = self._case_messages("order_update", "order")
        self.assertEqual([item["orderUpdateId"] for item in update_orders], [0, 1])
        update_outcome = self._expected_outcome(
            "FixtureVendor", "R1", "updated-order"
        )
        self.assertEqual(update_outcome["accepted_order_update_ids"], [0, 1])

        cancel_actions = self._case_messages("cancel_order", "instantActions")
        self.assertEqual(cancel_actions[0]["actions"][0]["actionType"], "cancelOrder")
        self.assertEqual(
            self._expected_outcome(
                "FixtureVendor", "R1", "cancelled-order"
            )["outcome"],
            "CANCELED_OR_CLEARED",
        )

        hibernate_actions = self._case_messages(
            "hibernate_clear", "instantActions"
        )
        self.assertEqual(
            hibernate_actions[0]["actions"][0]["actionType"],
            "startHibernation",
        )
        hibernate_connection = self._case_messages(
            "hibernate_clear", "connection"
        )[0]
        self.assertEqual(
            hibernate_connection["connectionState"], "HIBERNATING"
        )
        hibernate_states = self._case_messages("hibernate_clear", "state")
        self.assertEqual(hibernate_states[-1]["nodeStates"], [])
        self.assertEqual(hibernate_states[-1]["edgeStates"], [])
        self.assertEqual(
            self._expected_outcome(
                "FixtureVendor", "R1", "hibernate-cleared-order"
            )["outcome"],
            "CANCELED_OR_CLEARED",
        )

        rejected_state = self._case_messages("rejected_order", "state")[0]
        references = {
            (item["referenceKey"], item["referenceValue"])
            for error in rejected_state["errors"]
            for item in error.get("errorReferences", [])
        }
        self.assertIn(("orderId", "rejected-order"), references)
        self.assertEqual(
            self._expected_outcome(
                "FixtureVendor", "R1", "rejected-order"
            )["outcome"],
            "REJECTED",
        )

    def test_order_outcome_truth_is_separate_and_robot_scoped(self) -> None:
        truth = self._truth("protocol_order_outcomes")
        wire_path = (ROOT / "fixtures" / "truth" / truth["wire_fixture"]).resolve()
        self.assertEqual(wire_path, WIRE_FIXTURE.resolve())

        outcomes = truth["expected"]["outcomes"]
        identities = {
            (
                row["robot_identity"]["manufacturer"],
                row["robot_identity"]["serialNumber"],
                row["orderId"],
            )
            for row in outcomes
        }
        self.assertEqual(len(identities), len(outcomes))

        shared = [row for row in outcomes if row["orderId"] == "shared-order"]
        self.assertEqual(len(shared), 2)
        self.assertEqual(
            {row["robot_identity"]["serialNumber"] for row in shared},
            {"R1", "R2"},
        )

        computed: dict[str, int] = {}
        for row in outcomes:
            computed[row["outcome"]] = computed.get(row["outcome"], 0) + 1
        self.assertEqual(computed, truth["expected"]["counts"])

    def test_finished_orders_per_observed_robot_hour_truth(self) -> None:
        truth = self._truth("finished_orders_per_observed_robot_hour")
        robots = truth["robots"]
        numerator = len(
            {
                (robot["robot"], order_id)
                for robot in robots
                for order_id in robot["accepted_inferred_finished_order_ids"]
            }
        )
        denominator = sum(
            robot["eligible_observed_seconds"] for robot in robots
        ) / 3600
        expected = truth["expected"]
        self.assertEqual(numerator, expected["numerator_unique_finished_orders"])
        self.assertEqual(
            denominator, expected["denominator_observed_robot_hours"]
        )
        self.assertEqual(numerator / denominator, expected["value"])
        self.assertNotIn("throughput", expected["qualified_id"])
        self.assertNotIn("forbidden_labels", expected)
        self.assertEqual(expected["scope"]["kind"], "OBSERVED_ROBOT_COHORT")
        self.assertEqual(expected["scope"]["subject_ids"], ["R1", "R2"])

    def _truth(self, name: str) -> dict[str, object]:
        path = ROOT / "fixtures" / "truth" / f"{name}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def _wire(self) -> dict[str, object]:
        return json.loads(WIRE_FIXTURE.read_text(encoding="utf-8"))

    def _vda_schema(self, family: str) -> dict[str, object]:
        return json.loads(
            (VENDOR_ROOT / f"{family}.schema").read_text(encoding="utf-8")
        )

    def _case_messages(self, case_id: str, family: str) -> list[dict[str, object]]:
        return [
            record["message"]
            for record in self._wire()["records"]
            if record["case_id"] == case_id
            and record["message_family"] == family
        ]

    def _expected_outcome(
        self, manufacturer: str, serial_number: str, order_id: str
    ) -> dict[str, object]:
        outcomes = self._truth("protocol_order_outcomes")["expected"]["outcomes"]
        matches = [
            row
            for row in outcomes
            if row["robot_identity"]
            == {"manufacturer": manufacturer, "serialNumber": serial_number}
            and row["orderId"] == order_id
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def _assert_nested_required_fields(
        self,
        family: str,
        message: dict[str, object],
        schema: dict[str, object],
    ) -> None:
        definitions = schema.get("definitions", {})
        arrays_by_family = {
            "order": (("nodes", "node"), ("edges", "edge")),
            "instantActions": (("actions", None),),
            "state": (
                ("nodeStates", "nodeState"),
                ("edgeStates", "edgeState"),
                ("actionStates", "actionState"),
                ("instantActionStates", "actionState"),
                ("errors", "error"),
            ),
            "connection": (),
        }
        for field, definition_name in arrays_by_family[family]:
            if definition_name is None:
                item_schema = schema["properties"][field]["items"]
            else:
                item_schema = definitions[definition_name]
            required = set(item_schema.get("required", []))
            for item in message[field]:
                self.assertLessEqual(required, set(item))

        if family == "state":
            for field, definition_name in (
                ("powerSupply", "powerSupply"),
                ("safetyState", "safetyState"),
            ):
                required = set(definitions[definition_name]["required"])
                self.assertLessEqual(required, set(message[field]))


if __name__ == "__main__":
    unittest.main()
