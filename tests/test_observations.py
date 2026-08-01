import dataclasses
import unittest
from pathlib import Path
from unittest import mock

from mekai_open.capture_adapter import (
    analyze_recorded_capture,
    normalize_capture_item,
    normalize_capture_summary,
)
from mekai_open.capture_jsonl import (
    CaptureMessageRecord,
    CaptureReader,
    CaptureSessionRecord,
)
from mekai_open.observations import (
    CaptureBoundaryKind,
    CaptureBoundaryObservation,
    CollectorSessionObservation,
    MessageDiscontinuityObservation,
    NormalizedVdaObservation,
)
from mekai_open.input_fingerprint import InputChangedError
from mekai_open.contracts import ResultStatus


ROOT = Path(__file__).parents[1]
FIXTURE = (
    ROOT / "fixtures" / "captures" / "state_stream_health.synthetic.capture.jsonl"
)


class RecordedObservationTests(unittest.TestCase):
    def test_capture_adapter_preserves_exact_valid_message_fields_without_raw_bytes(
        self,
    ) -> None:
        with CaptureReader(FIXTURE, "synthetic-source") as reader:
            next(reader)
            next(reader)
            message = next(reader)
            self.assertIsInstance(message, CaptureMessageRecord)
            observation = normalize_capture_item(message)
            while True:
                try:
                    next(reader)
                except StopIteration:
                    break
            summary = normalize_capture_summary(reader.summary)

        self.assertIsInstance(observation, NormalizedVdaObservation)
        self.assertEqual(observation.source_id, "synthetic-source")
        self.assertEqual(observation.locator, "line:3")
        self.assertEqual(observation.observation_time_ns, 0)
        self.assertEqual(observation.continuity_epoch, 1)
        self.assertEqual(observation.topic, "synthetic/R-A/connection")
        self.assertEqual(observation.robot_identity.manufacturer, "SyntheticVendor")
        self.assertEqual(observation.robot_identity.serial_number, "R-A")
        self.assertEqual(observation.header_id, 1)
        self.assertEqual(
            observation.source_timestamp, "2026-01-01T00:00:00.000Z"
        )
        self.assertFalse(observation.retained)
        self.assertFalse(observation.producer_duplicate)
        self.assertEqual(observation.payload_sha256, message.payload_sha256)
        self.assertIs(
            observation.validated_payload,
            message.validated_message.decoded,
        )
        self.assertNotIn(
            "raw_payload",
            {field.name for field in dataclasses.fields(observation)},
        )
        self.assertNotIn(
            "raw_bytes",
            {field.name for field in dataclasses.fields(observation)},
        )
        self.assertTrue(summary.complete)
        self.assertEqual(summary.input_sha256, reader.summary.input_sha256)

    def test_reused_producer_session_labels_map_to_distinct_continuity_epochs(
        self,
    ) -> None:
        sessions: list[CollectorSessionObservation] = []
        with CaptureReader(FIXTURE, "synthetic-source") as reader:
            for item in reader:
                if isinstance(item, CaptureSessionRecord):
                    normalized = normalize_capture_item(item)
                    self.assertIsInstance(normalized, CollectorSessionObservation)
                    sessions.append(normalized)
        starts = [item for item in sessions if item.kind.value == "session_start"]
        self.assertEqual(
            [item.producer_session_id for item in starts],
            ["reused-session", "reused-session"],
        )
        self.assertEqual([item.continuity_epoch for item in starts], [1, 15])
        self.assertEqual(
            [item.continuity_epoch for item in sessions],
            [1, 1, 15, 15],
        )

    def test_schema_invalid_vda_message_remains_a_noneligible_health_fact(self) -> None:
        normalized = None
        original = None
        with CaptureReader(FIXTURE, "synthetic-source") as reader:
            for item in reader:
                if isinstance(item, CaptureMessageRecord) and item.locator == "line:21":
                    original = item
                    normalized = normalize_capture_item(item)
        self.assertIsNotNone(original)
        self.assertFalse(original.eligible_for_functions)
        self.assertIsInstance(normalized, MessageDiscontinuityObservation)
        self.assertTrue(normalized.capture_accepted)
        self.assertFalse(normalized.vda_valid)
        self.assertEqual(normalized.continuity_epoch, 15)
        self.assertEqual(normalized.payload_sha256, original.payload_sha256)
        self.assertEqual(normalized.vda_diagnostic_codes, ("SCHEMA_VIOLATION",))

    def test_normalized_message_and_nested_payload_are_immutable(self) -> None:
        with CaptureReader(FIXTURE, "synthetic-source") as reader:
            next(reader)
            next(reader)
            observation = normalize_capture_item(next(reader))
        self.assertIsInstance(observation, NormalizedVdaObservation)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            observation.topic = "changed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            observation.validated_payload["headerId"] = 99  # type: ignore[index]

    def test_orchestration_turns_observed_input_mutation_into_not_computable(self) -> None:
        class MutatingReader:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self._read = False

            def __enter__(self) -> "MutatingReader":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def __iter__(self) -> "MutatingReader":
                return self

            def __next__(self) -> CaptureBoundaryObservation:
                if not self._read:
                    self._read = True
                    return CaptureBoundaryObservation(
                        source_id="synthetic-source",
                        locator="line:1",
                        observation_time_ns=0,
                        sequence=0,
                        kind=CaptureBoundaryKind.START,
                        declared_complete=None,
                    )
                raise InputChangedError("INPUT_CHANGED")

        with mock.patch(
            "mekai_open.capture_adapter.CaptureReader",
            MutatingReader,
        ), mock.patch(
            "mekai_open.capture_adapter.normalize_capture_item",
            side_effect=lambda item: item,
        ):
            result = analyze_recorded_capture(
                "ignored-by-fake-reader.jsonl", "synthetic-source"
            )
        self.assertEqual(result.status, ResultStatus.NOT_COMPUTABLE)
        self.assertIsNone(result.window)
        self.assertEqual(result.diagnostics, ("INPUT_CHANGED",))


if __name__ == "__main__":
    unittest.main()
