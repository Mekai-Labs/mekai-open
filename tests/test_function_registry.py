import json
import unittest
from pathlib import Path

from mekai_open.function_registry import get_function_spec, list_function_specs


class FunctionRegistryTests(unittest.TestCase):
    def test_registry_is_unique(self) -> None:
        specs = list_function_specs()
        ids = [item.qualified_id for item in specs]
        self.assertEqual(len(ids), len(set(ids)))

    def test_rate_name_and_semantics_are_exact(self) -> None:
        qualified_id = (
            "vda.inferred_protocol_finished_orders_per_observed_robot_hour@0.1.0"
        )
        spec = get_function_spec(qualified_id)
        self.assertEqual(spec.qualified_id, qualified_id)
        self.assertNotIn("throughput", spec.function_id)
        self.assertIn("eligible observed robot-hours", spec.method)

    def test_lifecycle_specs_require_named_last_node(self) -> None:
        lifecycle_ids = (
            "vda.inferred_protocol_order_outcomes@0.1.0",
            "vda.inferred_protocol_order_execution_duration@0.1.0",
            "vda.inferred_protocol_finished_orders_per_observed_robot_hour@0.1.0",
        )
        for qualified_id in lifecycle_ids:
            with self.subTest(qualified_id=qualified_id):
                spec = get_function_spec(qualified_id)
                state = next(
                    item
                    for item in spec.required_fields
                    if item.message_family == "state"
                )
                self.assertIn("lastNodeId", state.fields)
                self.assertIn("lastNodeSequenceId", state.fields)
                requirements = " ".join(spec.missing_data_requirements)
                self.assertIn(
                    "Ignore lastNodeSequenceId whenever lastNodeId is empty",
                    requirements,
                )

    def test_hibernation_semantics_are_explicit(self) -> None:
        connection = get_function_spec(
            "vda.reported_connection_state_duration@0.1.0"
        )
        self.assertIn("HIBERNATING", " ".join(connection.missing_data_requirements))

        state_health = get_function_spec("vda.state_stream_health@0.1.0")
        health_requirements = " ".join(state_health.missing_data_requirements)
        self.assertIn("expected", health_requirements)
        self.assertIn("without confirmation", health_requirements)

        rate = get_function_spec(
            "vda.inferred_protocol_finished_orders_per_observed_robot_hour@0.1.0"
        )
        rate_requirements = " ".join(rate.missing_data_requirements)
        self.assertIn("Exclude confirmed HIBERNATING", rate_requirements)
        self.assertIn("clears the active order", rate_requirements)

    def test_fixture_references_exist_and_match_the_function(self) -> None:
        fixture_root = Path(__file__).parents[1] / "fixtures" / "truth"
        available = {
            f"truth.{path.stem}": path for path in fixture_root.glob("*.json")
        }
        for spec in list_function_specs():
            for fixture_id in spec.fixture_ids:
                with self.subTest(
                    function=spec.qualified_id,
                    fixture=fixture_id,
                ):
                    self.assertIn(fixture_id, available)
                    fixture = json.loads(
                        available[fixture_id].read_text(encoding="utf-8")
                    )
                    self.assertEqual(
                        fixture["expected"]["qualified_id"],
                        spec.qualified_id,
                    )

    def test_unknown_function_fails_closed(self) -> None:
        with self.assertRaises(KeyError):
            get_function_spec("vda.unknown@0.1.0")


if __name__ == "__main__":
    unittest.main()
