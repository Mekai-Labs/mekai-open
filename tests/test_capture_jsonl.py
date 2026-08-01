import ast
import base64
import hashlib
import inspect
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

import mekai_open
import mekai_open.capture_jsonl as capture_jsonl
from mekai_open.capture_jsonl import (
    CAPTURE_ENVELOPE_HEADROOM_BYTES,
    CAPTURE_SCHEMA_ID,
    CaptureControlRecord,
    CaptureDiagnosticCode,
    CaptureDropRecord,
    CaptureInputError,
    CaptureMessageRecord,
    CaptureReader,
    CaptureReaderArgumentError,
    CaptureReaderStateError,
    CaptureRecordKind,
    CaptureSessionRecord,
    InvalidCaptureRecord,
    capture_record_byte_limit,
)
from mekai_open.input_fingerprint import InputChangedError
from mekai_open.json_safety import (
    MAX_JSON_NESTING_DEPTH,
    MAX_JSON_NUMBER_CHARACTERS,
    MAX_JSON_STRUCTURAL_SEPARATORS,
    StrictJsonDiagnosticCode,
)
from mekai_open.vda_schemas import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_MESSAGE_BYTES_CEILING,
    InvalidParsingLimitError,
    ValidationDiagnosticCode,
    VdaMessageFamily,
)


ROOT = Path(__file__).parents[1]
WIRE_FIXTURE = ROOT / "fixtures" / "vda5050" / "order_lifecycle_wire.json"
CAPTURE_SCHEMA = ROOT / "schemas" / "capture-record-0.1.schema.json"


class CaptureJsonlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = json.loads(WIRE_FIXTURE.read_text(encoding="utf-8"))
        if fixture["synthetic"] is not True:
            raise AssertionError("capture tests require explicitly synthetic input")
        cls.messages = {}
        for record in fixture["records"]:
            cls.messages.setdefault(
                record["message_family"], record["message"]
            )

    def test_complete_capture_preserves_all_families_drop_and_exact_bytes(
        self,
    ) -> None:
        records = [
            self._record("capture_start", 0, monotonic=100),
            self._record("session_start", 1, session="session-a", monotonic=110),
        ]
        expected_payloads: dict[VdaMessageFamily, bytes] = {}
        for sequence, family in enumerate(VdaMessageFamily, start=2):
            payload = self._json_bytes(self.messages[family.value])
            expected_payloads[family] = payload
            records.append(
                self._message(
                    sequence,
                    family.value,
                    payload,
                    session="session-a",
                    monotonic=100 + sequence * 10,
                )
            )
        records.extend(
            (
                self._record(
                    "drop",
                    6,
                    session="session-a",
                    drop_count=3,
                    drop_reason="collector_queue_full",
                    monotonic=160,
                ),
                self._record(
                    "session_end", 7, session="session-a", monotonic=170
                ),
                self._record("capture_end", 8, complete=True, monotonic=180),
            )
        )

        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, self._encode_records(records))
            items, summary = self._read(path)

        self.assertEqual(len(items), 9)
        messages = [
            item for item in items if isinstance(item, CaptureMessageRecord)
        ]
        self.assertEqual(
            {item.message_family for item in messages}, set(VdaMessageFamily)
        )
        for item in messages:
            expected = expected_payloads[item.message_family]
            self.assertEqual(item.raw_payload, expected)
            self.assertEqual(
                item.payload_sha256, hashlib.sha256(expected).hexdigest()
            )
            self.assertIsNotNone(item.validated_message)
            self.assertEqual(item.validation_diagnostics, ())
            self.assertEqual(item.source_id, "synthetic-capture")
            self.assertRegex(item.locator, r"^line:\d+$")
            self.assertEqual(item.collector_session_start_sequence, 1)
            self.assertTrue(item.eligible_for_functions)

        drop = next(item for item in items if isinstance(item, CaptureDropRecord))
        self.assertEqual(drop.drop_count, 3)
        self.assertEqual(drop.drop_reason, "collector_queue_full")
        self.assertEqual(drop.collector_session_start_sequence, 1)
        self.assertTrue(drop.capture_accepted)
        sessions = [
            item for item in items if isinstance(item, CaptureSessionRecord)
        ]
        self.assertEqual(
            [item.collector_session_start_sequence for item in sessions],
            [1, 1],
        )
        self.assertTrue(summary.complete)
        self.assertTrue(summary.verified_unchanged)
        self.assertFalse(summary.structurally_compromised)
        self.assertEqual(summary.accepted_record_count, 9)

    def test_multiple_sequential_collector_sessions(self) -> None:
        records = [
            self._record("capture_start", 0),
            self._record("session_start", 1, session="session-a"),
            self._record("session_end", 2, session="session-a"),
            self._record("session_start", 3, session="session-b"),
            self._record("session_end", 4, session="session-b"),
            self._record("capture_end", 5, complete=True),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        sessions = [
            item for item in items if isinstance(item, CaptureSessionRecord)
        ]
        self.assertEqual(
            [item.collector_session_id for item in sessions],
            ["session-a", "session-a", "session-b", "session-b"],
        )
        self.assertEqual(
            [item.collector_session_start_sequence for item in sessions],
            [1, 1, 3, 3],
        )
        self.assertTrue(all(item.capture_accepted for item in sessions))
        self.assertTrue(summary.complete)

    def test_reused_session_label_has_distinct_constant_memory_epochs(self) -> None:
        payload = self._json_bytes(self.messages["connection"])
        records = [
            self._record("capture_start", 0),
            self._record("session_start", 1, session="reused-label"),
            self._message(2, "connection", payload, session="reused-label"),
            self._record(
                "drop",
                3,
                session="reused-label",
                drop_count=1,
                drop_reason="synthetic_drop",
            ),
            self._record("session_end", 4, session="reused-label"),
            self._record("session_start", 5, session="reused-label"),
            self._message(6, "connection", payload, session="reused-label"),
            self._record("session_end", 7, session="reused-label"),
            self._record("capture_end", 8, complete=True),
        ]

        items, summary = self._read_payload(self._encode_records(records))
        session_facts = [
            item
            for item in items
            if isinstance(
                item,
                (CaptureSessionRecord, CaptureDropRecord, CaptureMessageRecord),
            )
        ]
        self.assertEqual(
            {item.collector_session_id for item in session_facts},
            {"reused-label"},
        )
        self.assertEqual(
            [item.collector_session_start_sequence for item in session_facts],
            [1, 1, 1, 1, 5, 5, 5],
        )
        self.assertTrue(summary.complete)

    def test_eof_without_capture_end_is_verified_but_incomplete(self) -> None:
        records = [self._record("capture_start", 0)]
        _, summary = self._read_payload(self._encode_records(records))
        self.assertFalse(summary.complete)
        self.assertTrue(summary.verified_unchanged)
        self.assertTrue(summary.structurally_compromised)
        self.assertIn(
            CaptureDiagnosticCode.MISSING_CAPTURE_END,
            {item.code for item in summary.diagnostics},
        )

    def test_declared_incomplete_capture_is_not_structural_corruption(self) -> None:
        records = [
            self._record("capture_start", 0),
            self._record("capture_end", 1, complete=False),
        ]
        _, summary = self._read_payload(self._encode_records(records))
        self.assertFalse(summary.complete)
        self.assertIs(summary.declared_complete, False)
        self.assertFalse(summary.structurally_compromised)
        self.assertIn(
            CaptureDiagnosticCode.CAPTURE_DECLARED_INCOMPLETE,
            {item.code for item in summary.diagnostics},
        )

    def test_blank_line_bom_and_invalid_utf8_are_invalid_records(self) -> None:
        valid_start = self._json_bytes(self._record("capture_start", 0))
        cases = (
            (b"\n", CaptureDiagnosticCode.EMPTY_RECORD),
            (
                b"\xef\xbb\xbf" + valid_start + b"\n",
                CaptureDiagnosticCode.MALFORMED_JSON,
            ),
            (b"\xff\n", CaptureDiagnosticCode.INVALID_UTF8),
        )
        for hostile, expected in cases:
            with self.subTest(expected=expected):
                item = self._first_item(hostile)
                self.assertIsInstance(item, InvalidCaptureRecord)
                self.assertIn(
                    expected,
                    {diagnostic.code for diagnostic in item.diagnostics},
                )

    def test_malformed_json_is_bounded_and_does_not_stop_later_records(self) -> None:
        payload = (
            b'{"schema":"mekai.capture_record/0.1",}\n'
            + self._encode_records(
                [
                    self._record("capture_start", 0),
                    self._record("capture_end", 1, complete=True),
                ]
            )
        )
        items, summary = self._read_payload(payload)
        self.assertIsInstance(items[0], InvalidCaptureRecord)
        self.assertEqual(
            items[0].diagnostics[0].code,
            CaptureDiagnosticCode.MALFORMED_JSON,
        )
        self.assertIsInstance(items[1], CaptureControlRecord)
        self.assertFalse(summary.complete)
        self.assertTrue(summary.verified_unchanged)

    def test_duplicate_envelope_keys_are_rejected_at_every_depth(self) -> None:
        top = (
            b'{"schema":"mekai.capture_record/0.1","kind":"capture_start",'
            b'"sequence":0,"sequence":1,"receive_time_ns":0}\n'
        )
        nested = (
            b'{"schema":"mekai.capture_record/0.1","kind":"capture_start",'
            b'"sequence":0,"receive_time_ns":0,"extra":{"x":1,"x":2}}\n'
        )
        for raw in (top, nested):
            with self.subTest(raw=raw[:40]):
                item = self._first_item(raw)
                self.assertIn(
                    CaptureDiagnosticCode.DUPLICATE_KEY,
                    {diagnostic.code for diagnostic in item.diagnostics},
                )

    def test_unpaired_surrogates_in_envelope_values_and_keys_are_rejected(
        self,
    ) -> None:
        value = (
            b'{"schema":"mekai.capture_record/0.1","kind":"capture_start",'
            b'"sequence":0,"receive_time_ns":0,"extra":"\\ud800"}\n'
        )
        key = (
            b'{"schema":"mekai.capture_record/0.1","kind":"capture_start",'
            b'"sequence":0,"receive_time_ns":0,"\\udfff":1}\n'
        )
        for raw in (value, key):
            with self.subTest(raw=raw[-20:]):
                item = self._first_item(raw)
                self.assertIn(
                    CaptureDiagnosticCode.INVALID_UNICODE,
                    {diagnostic.code for diagnostic in item.diagnostics},
                )

    def test_shared_strict_json_resource_rules_apply_to_envelopes(self) -> None:
        tokens = (b"NaN", b"Infinity", b"-Infinity")
        for token in tokens:
            with self.subTest(token=token):
                raw = (
                    b'{"schema":"mekai.capture_record/0.1",'
                    b'"kind":"capture_start","sequence":0,'
                    b'"receive_time_ns":' + token + b"}\n"
                )
                item = self._first_item(raw)
                self.assertEqual(
                    item.diagnostics[0].code,
                    CaptureDiagnosticCode.NON_FINITE_NUMBER,
                )

        number = b"1" * (MAX_JSON_NUMBER_CHARACTERS + 1)
        raw = (
            b'{"schema":"mekai.capture_record/0.1",'
            b'"kind":"capture_start","sequence":' + number +
            b',"receive_time_ns":0}\n'
        )
        item = self._first_item(raw)
        self.assertEqual(
            item.diagnostics[0].code, CaptureDiagnosticCode.RESOURCE_LIMIT
        )

        nested = b"[" * MAX_JSON_NESTING_DEPTH + b"0" + b"]" * MAX_JSON_NESTING_DEPTH
        raw = b'{"extra":' + nested + b"}\n"
        item = self._first_item(raw)
        self.assertEqual(
            item.diagnostics[0].code,
            CaptureDiagnosticCode.NESTING_TOO_DEEP,
        )

        dense = b"[0" + b",0" * MAX_JSON_STRUCTURAL_SEPARATORS + b"]"
        item = self._first_item(b'{"extra":' + dense + b"}\n")
        self.assertEqual(
            item.diagnostics[0].code, CaptureDiagnosticCode.RESOURCE_LIMIT
        )

    def test_strict_json_codes_are_representable_by_both_consumers(self) -> None:
        strict_codes = {item.value for item in StrictJsonDiagnosticCode}
        self.assertLessEqual(
            strict_codes, {item.value for item in ValidationDiagnosticCode}
        )
        self.assertLessEqual(
            strict_codes, {item.value for item in CaptureDiagnosticCode}
        )

    def test_physical_line_at_limit_is_accepted(self) -> None:
        maximum = capture_record_byte_limit(1)
        start = self._json_bytes(self._record("capture_start", 0))
        padding = maximum - len(start) - 1
        self.assertGreater(padding, 0)
        exact = start + b" " * padding + b"\n"
        self.assertEqual(len(exact), maximum)
        payload = exact + self._encode_records(
            [self._record("capture_end", 1, complete=True)]
        )
        items, summary = self._read_payload(payload, max_message_bytes=1)
        self.assertIsInstance(items[0], CaptureControlRecord)
        self.assertTrue(summary.complete)

    def test_over_limit_line_skips_json_and_base64_then_drains(self) -> None:
        maximum = capture_record_byte_limit(1)
        start = self._json_bytes(self._record("capture_start", 99))
        oversized = (
            start
            + b" " * (maximum - len(start) + 2 * 64 * 1024)
            + b"\n"
        )
        self.assertGreater(len(oversized), maximum + 2 * 64 * 1024)
        payload = oversized + self._encode_records(
            [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, payload)
            with CaptureReader(
                path, "synthetic-capture", max_message_bytes=1
            ) as reader:
                with (
                    mock.patch(
                        "mekai_open.capture_jsonl.decode_strict_json"
                    ) as decode,
                    mock.patch(
                        "mekai_open.capture_jsonl.base64.b64decode"
                    ) as b64decode,
                ):
                    first = next(reader)
                decode.assert_not_called()
                b64decode.assert_not_called()
                rest = tuple(reader)
                summary = reader.summary
        self.assertEqual(
            first.diagnostics[0].code,
            CaptureDiagnosticCode.RECORD_TOO_LARGE,
        )
        self.assertEqual(len(rest), 2)
        self.assertTrue(summary.verified_unchanged)
        self.assertFalse(summary.complete)

    def test_capture_record_limit_tracks_message_limits(self) -> None:
        for maximum in (DEFAULT_MAX_MESSAGE_BYTES, MAX_MESSAGE_BYTES_CEILING):
            with self.subTest(maximum=maximum):
                expected = (
                    4 * ((maximum + 2) // 3)
                    + CAPTURE_ENVELOPE_HEADROOM_BYTES
                    + 1
                )
                self.assertEqual(capture_record_byte_limit(maximum), expected)
        with self.assertRaises(InvalidParsingLimitError):
            capture_record_byte_limit(MAX_MESSAGE_BYTES_CEILING + 1)

    def test_canonical_and_invalid_base64(self) -> None:
        payload = self._json_bytes(self.messages["connection"])
        canonical = base64.b64encode(payload).decode("ascii")
        self.assertEqual(base64.b64decode(canonical), payload)
        records = self._capture_with_message("connection", payload)
        items, summary = self._read_payload(self._encode_records(records))
        message = next(
            item for item in items if isinstance(item, CaptureMessageRecord)
        )
        self.assertEqual(message.raw_payload, payload)
        self.assertTrue(summary.complete)

        for invalid in ("!!!!", "AB==", "YQ", "é"):
            with self.subTest(invalid=invalid):
                records = self._capture_with_message("connection", payload)
                records[2]["payload_base64"] = invalid
                items, summary = self._read_payload(self._encode_records(records))
                item = items[2]
                self.assertIsInstance(item, InvalidCaptureRecord)
                self.assertIn(
                    CaptureDiagnosticCode.INVALID_BASE64,
                    {diagnostic.code for diagnostic in item.diagnostics},
                )
                self.assertFalse(summary.complete)

    def test_decoded_payload_limit_precedes_vda_validation(self) -> None:
        records = self._capture_with_message("connection", b"ab")
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, self._encode_records(records))
            with mock.patch(
                "mekai_open.capture_jsonl.validate_vda_payload"
            ) as validate:
                items, summary = self._read(path, max_message_bytes=1)
        validate.assert_not_called()
        self.assertIsInstance(items[2], InvalidCaptureRecord)
        self.assertIn(
            CaptureDiagnosticCode.PAYLOAD_TOO_LARGE,
            {item.code for item in items[2].diagnostics},
        )
        self.assertFalse(summary.complete)

    def test_base64_resource_failure_is_a_bounded_diagnostic(self) -> None:
        records = self._capture_with_message("connection", b"payload")
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, self._encode_records(records))
            with mock.patch(
                "mekai_open.capture_jsonl.base64.b64decode",
                side_effect=MemoryError,
            ):
                items, summary = self._read(path)
        message = items[2]
        self.assertIsInstance(message, InvalidCaptureRecord)
        self.assertEqual(
            [diagnostic.code for diagnostic in message.diagnostics],
            [CaptureDiagnosticCode.RESOURCE_LIMIT],
        )
        self.assertNotIn(
            base64.b64encode(b"payload").decode("ascii"),
            str(message.diagnostics),
        )
        self.assertFalse(summary.complete)

    def test_empty_payload_reaches_existing_empty_payload_diagnostic(self) -> None:
        records = self._capture_with_message("connection", b"")
        items, summary = self._read_payload(self._encode_records(records))
        message = items[2]
        self.assertIsInstance(message, CaptureMessageRecord)
        self.assertEqual(message.raw_payload, b"")
        self.assertEqual(
            message.payload_sha256, hashlib.sha256(b"").hexdigest()
        )
        self.assertIsNone(message.validated_message)
        self.assertEqual(
            [item.code for item in message.validation_diagnostics],
            [ValidationDiagnosticCode.EMPTY_PAYLOAD],
        )
        self.assertTrue(summary.complete)

    def test_unsupported_and_wrong_declared_families(self) -> None:
        connection = self._json_bytes(self.messages["connection"])
        unsupported = self._capture_with_message("connection", connection)
        unsupported[2]["message_family"] = "visualization"
        items, summary = self._read_payload(self._encode_records(unsupported))
        self.assertIsInstance(items[2], InvalidCaptureRecord)
        self.assertFalse(summary.complete)

        wrong = self._capture_with_message("state", connection)
        items, summary = self._read_payload(self._encode_records(wrong))
        message = items[2]
        self.assertIsInstance(message, CaptureMessageRecord)
        self.assertIsNone(message.validated_message)
        self.assertTrue(message.validation_diagnostics)
        self.assertEqual(message.raw_payload, connection)
        self.assertTrue(summary.complete)

    def test_schema_invalid_vda_payload_is_retained_but_never_valid(self) -> None:
        payload = b' { "version": "3.0.0" } '
        records = self._capture_with_message("connection", payload)
        items, summary = self._read_payload(self._encode_records(records))
        message = items[2]
        self.assertIsInstance(message, CaptureMessageRecord)
        self.assertEqual(message.raw_payload, payload)
        self.assertEqual(
            message.payload_sha256, hashlib.sha256(payload).hexdigest()
        )
        self.assertIsNone(message.validated_message)
        self.assertTrue(message.validation_diagnostics)
        self.assertTrue(message.capture_accepted)
        self.assertFalse(message.eligible_for_functions)
        self.assertTrue(summary.complete)
        self.assertEqual(summary.accepted_record_count, len(records))

    def test_function_eligibility_preserves_capture_and_vda_boundaries(self) -> None:
        valid = self._json_bytes(self.messages["connection"])
        invalid = b'{"version":"3.0.0"}'
        records = [
            self._record("capture_start", 0),
            self._record("session_start", 1, session="session-a"),
            self._message(2, "connection", valid, session="session-a"),
            self._message(3, "connection", invalid, session="session-a"),
            self._message(4, "connection", valid, session="session-b"),
            self._message(5, "connection", invalid, session="session-b"),
            self._record("session_end", 6, session="session-a"),
            self._record("capture_end", 7, complete=True),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        messages = [
            item for item in items if isinstance(item, CaptureMessageRecord)
        ]

        self.assertEqual(
            [
                (item.capture_accepted, item.validated_message is not None)
                for item in messages
            ],
            [(True, True), (True, False), (False, True), (False, False)],
        )
        self.assertEqual(
            [item.eligible_for_functions for item in messages],
            [True, False, False, False],
        )
        self.assertEqual(
            [item.collector_session_start_sequence for item in messages],
            [1, 1, None, None],
        )
        self.assertEqual(summary.accepted_record_count, 6)
        self.assertFalse(summary.complete)

    def test_sequence_start_duplicate_and_gap_are_diagnosed(self) -> None:
        cases = {
            "nonzero": [
                self._record("capture_start", 1),
                self._record("capture_end", 2, complete=True),
            ],
            "duplicate": [
                self._record("capture_start", 0),
                self._record("session_start", 1, session="s"),
                self._record(
                    "drop",
                    1,
                    session="s",
                    drop_count=1,
                    drop_reason="synthetic_drop",
                ),
                self._record("session_end", 2, session="s"),
                self._record("capture_end", 3, complete=True),
            ],
            "gap": [
                self._record("capture_start", 0),
                self._record("capture_end", 2, complete=True),
            ],
        }
        for name, records in cases.items():
            with self.subTest(name=name):
                _, summary = self._read_payload(self._encode_records(records))
                self.assertIn(
                    CaptureDiagnosticCode.SEQUENCE_MISMATCH,
                    {item.code for item in summary.diagnostics},
                )
                self.assertFalse(summary.complete)

    def test_message_requires_matching_active_session(self) -> None:
        payload = self._json_bytes(self.messages["connection"])
        records = [
            self._record("capture_start", 0),
            self._message(1, "connection", payload, session="missing"),
            self._record("capture_end", 2, complete=True),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        message = items[1]
        self.assertIsInstance(message, CaptureMessageRecord)
        self.assertFalse(message.capture_accepted)
        self.assertIsNotNone(message.validated_message)
        self.assertEqual(message.validation_diagnostics, ())
        self.assertIsNone(message.collector_session_start_sequence)
        self.assertFalse(message.eligible_for_functions)
        self.assertIn(
            CaptureDiagnosticCode.SESSION_REQUIRED,
            {item.code for item in message.capture_diagnostics},
        )
        self.assertFalse(summary.complete)

    def test_message_and_drop_reject_a_different_active_session(self) -> None:
        payload = self._json_bytes(self.messages["connection"])
        records = [
            self._record("capture_start", 0),
            self._record("session_start", 1, session="session-a"),
            self._message(2, "connection", payload, session="session-b"),
            self._record(
                "drop",
                3,
                session="session-b",
                drop_count=1,
                drop_reason="synthetic_drop",
            ),
            self._record("session_end", 4, session="session-a"),
            self._record("capture_end", 5, complete=True),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        message = items[2]
        drop = items[3]
        self.assertIsInstance(message, CaptureMessageRecord)
        self.assertIsInstance(drop, CaptureDropRecord)
        self.assertFalse(message.capture_accepted)
        self.assertFalse(drop.capture_accepted)
        self.assertIsNone(message.collector_session_start_sequence)
        self.assertIsNone(drop.collector_session_start_sequence)
        self.assertEqual(items[4].collector_session_start_sequence, 1)
        self.assertIsNotNone(message.validated_message)
        self.assertEqual(
            [
                diagnostic.code
                for item in (message, drop)
                for diagnostic in item.capture_diagnostics
            ],
            [
                CaptureDiagnosticCode.SESSION_ID_MISMATCH,
                CaptureDiagnosticCode.SESSION_ID_MISMATCH,
            ],
        )
        self.assertFalse(summary.complete)

    def test_rejected_session_start_does_not_open_a_session_epoch(self) -> None:
        payload = self._json_bytes(self.messages["connection"])
        records = [
            self._record("capture_start", 0, monotonic=100),
            self._record(
                "session_start", 1, session="session-a", monotonic=90
            ),
            self._message(
                2,
                "connection",
                payload,
                session="session-a",
                monotonic=110,
            ),
            self._record("capture_end", 3, complete=True, monotonic=120),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        session_start = items[1]
        message = items[2]
        self.assertIsInstance(session_start, CaptureSessionRecord)
        self.assertFalse(session_start.capture_accepted)
        self.assertIsNone(session_start.collector_session_start_sequence)
        self.assertIn(
            CaptureDiagnosticCode.MONOTONIC_TIME_REGRESSION,
            {item.code for item in session_start.capture_diagnostics},
        )
        self.assertIsInstance(message, CaptureMessageRecord)
        self.assertFalse(message.capture_accepted)
        self.assertIsNone(message.collector_session_start_sequence)
        self.assertIn(
            CaptureDiagnosticCode.SESSION_REQUIRED,
            {item.code for item in message.capture_diagnostics},
        )
        self.assertFalse(summary.complete)

    def test_overlapping_sessions_and_mismatched_end_are_diagnosed(self) -> None:
        records = [
            self._record("capture_start", 0),
            self._record("session_start", 1, session="session-a"),
            self._record("session_start", 2, session="session-b"),
            self._record("session_end", 3, session="session-b"),
            self._record("capture_end", 4, complete=True),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        self.assertFalse(items[2].capture_accepted)
        self.assertFalse(items[3].capture_accepted)
        self.assertEqual(items[1].collector_session_start_sequence, 1)
        self.assertIsNone(items[2].collector_session_start_sequence)
        self.assertIsNone(items[3].collector_session_start_sequence)
        codes = {item.code for item in summary.diagnostics}
        self.assertIn(CaptureDiagnosticCode.SESSION_ALREADY_ACTIVE, codes)
        self.assertIn(CaptureDiagnosticCode.SESSION_ID_MISMATCH, codes)
        self.assertIn(
            CaptureDiagnosticCode.CAPTURE_END_WITH_ACTIVE_SESSION, codes
        )
        self.assertFalse(summary.complete)

    def test_capture_boundaries_missing_duplicate_and_trailing(self) -> None:
        cases = {
            "missing_start": [self._record("capture_end", 0, complete=True)],
            "duplicate_start": [
                self._record("capture_start", 0),
                self._record("capture_start", 1),
                self._record("capture_end", 2, complete=True),
            ],
            "duplicate_end": [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
                self._record("capture_end", 2, complete=True),
            ],
            "trailing": [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
                self._record("capture_start", 2),
            ],
        }
        expected = {
            "missing_start": CaptureDiagnosticCode.MISSING_CAPTURE_START,
            "duplicate_start": CaptureDiagnosticCode.DUPLICATE_CAPTURE_START,
            "duplicate_end": CaptureDiagnosticCode.DUPLICATE_CAPTURE_END,
            "trailing": CaptureDiagnosticCode.RECORD_AFTER_CAPTURE_END,
        }
        for name, records in cases.items():
            with self.subTest(name=name):
                _, summary = self._read_payload(self._encode_records(records))
                self.assertIn(
                    expected[name],
                    {item.code for item in summary.diagnostics},
                )
                self.assertFalse(summary.complete)

    def test_monotonic_regression_compromises_capture(self) -> None:
        records = [
            self._record("capture_start", 0, monotonic=20),
            self._record("capture_end", 1, complete=True, monotonic=10),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        self.assertFalse(items[1].capture_accepted)
        self.assertIn(
            CaptureDiagnosticCode.MONOTONIC_TIME_REGRESSION,
            {item.code for item in items[1].capture_diagnostics},
        )
        self.assertFalse(summary.complete)

    def test_utc_regression_is_diagnosed_without_rewriting_time(self) -> None:
        records = [
            self._record("capture_start", 0, receive_time_ns=100),
            self._record("capture_end", 1, receive_time_ns=50, complete=True),
        ]
        items, summary = self._read_payload(self._encode_records(records))
        end = items[1]
        self.assertEqual(end.observation_time_ns, 50)
        self.assertTrue(end.capture_accepted)
        self.assertIn(
            CaptureDiagnosticCode.UTC_TIME_REGRESSION,
            {item.code for item in end.capture_diagnostics},
        )
        self.assertTrue(summary.complete)

    def test_symlink_and_non_regular_inputs_are_rejected_safely(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self._write(
                directory,
                self._encode_records(
                    [
                        self._record("capture_start", 0),
                        self._record("capture_end", 1, complete=True),
                    ]
                ),
                name="target.jsonl",
            )
            symlink = root / "link.jsonl"
            symlink.symlink_to(target)
            for path in (symlink, root):
                with self.subTest(kind=path.name):
                    with self.assertRaises(CaptureInputError) as caught:
                        with CaptureReader(path, "synthetic-capture"):
                            pass
                    self.assertNotIn(str(root), str(caught.exception))

    def test_mutation_and_replacement_during_iteration_are_input_changed(
        self,
    ) -> None:
        original = self._encode_records(
            [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
            ]
        )
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                with tempfile.TemporaryDirectory() as directory:
                    path = self._write(directory, original)
                    with CaptureReader(path, "synthetic-capture") as reader:
                        next(reader)
                        if replacement:
                            candidate = Path(directory) / "replacement.jsonl"
                            candidate.write_bytes(original + b" ")
                            os.replace(candidate, path)
                        else:
                            with path.open("ab") as stream:
                                stream.write(b" ")
                        with self.assertRaisesRegex(
                            InputChangedError, "INPUT_CHANGED"
                        ) as caught:
                            tuple(reader)
                        self.assertNotIn(str(path), str(caught.exception))
                        with self.assertRaises(CaptureReaderStateError):
                            reader.summary

    def test_capture_file_io_failures_have_safe_boundary_errors(self) -> None:
        host_path = str(Path("sensitive-capture.jsonl").absolute())
        with mock.patch(
            "mekai_open.capture_jsonl.fingerprint_regular_file",
            side_effect=PermissionError(host_path),
        ):
            with self.assertRaises(CaptureInputError) as caught:
                with CaptureReader("capture.jsonl", "synthetic-capture"):
                    pass
        self.assertNotIn(host_path, str(caught.exception))

        payload = self._encode_records(
            [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, payload)
            with CaptureReader(path, "synthetic-capture") as reader:
                with mock.patch(
                    "mekai_open.capture_jsonl.verify_unchanged",
                    side_effect=PermissionError(host_path),
                ):
                    with self.assertRaises(InputChangedError) as caught:
                        tuple(reader)
        self.assertNotIn(host_path, str(caught.exception))

    def test_early_termination_never_exposes_a_verified_summary(self) -> None:
        payload = self._encode_records(
            [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, payload)
            with CaptureReader(path, "synthetic-capture") as reader:
                next(reader)
                with self.assertRaises(CaptureReaderStateError):
                    reader.summary
            with self.assertRaises(CaptureReaderStateError):
                reader.summary

    def test_records_diagnostics_and_summary_do_not_contain_host_path(self) -> None:
        payload = b"\n" + self._encode_records(
            [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, payload)
            items, summary = self._read(path)
            combined = repr((items, summary))
            self.assertNotIn(str(path), combined)
            self.assertNotIn(str(path.parent), combined)
        with self.assertRaises(CaptureReaderArgumentError):
            CaptureReader("capture.jsonl", "/absolute/source")
        self.assertNotIn("capture_jsonl", mekai_open.__all__)

    def test_reader_streams_without_whole_file_apis(self) -> None:
        tree = ast.parse(inspect.getsource(capture_jsonl))
        forbidden = {"read", "read_text", "readlines", "splitlines"}
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in forbidden
        }
        self.assertEqual(calls, set())

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-large-capture.jsonl"
            with path.open("wb") as stream:
                stream.write(self._encode_records([self._record("capture_start", 0)]))
                stream.write(
                    self._encode_records(
                        [self._record("session_start", 1, session="session-a")]
                    )
                )
                for sequence in range(2, 5002):
                    stream.write(
                        self._encode_records(
                            [
                                self._record(
                                    "drop",
                                    sequence,
                                    session="session-a",
                                    drop_count=1,
                                    drop_reason="synthetic_drop",
                                )
                            ]
                        )
                    )
                stream.write(
                    self._encode_records(
                        [
                            self._record(
                                "session_end", 5002, session="session-a"
                            ),
                            self._record("capture_end", 5003, complete=True),
                        ]
                    )
                )
            with CaptureReader(path, "synthetic-large") as reader:
                count = sum(1 for _ in reader)
                summary = reader.summary
        self.assertEqual(count, 5004)
        self.assertEqual(summary.physical_record_count, 5004)
        self.assertTrue(summary.complete)

    def test_file_level_diagnostic_count_is_bounded(self) -> None:
        payload = b"\n" * 300 + self._encode_records(
            [
                self._record("capture_start", 0),
                self._record("capture_end", 1, complete=True),
            ]
        )
        _, summary = self._read_payload(payload)
        self.assertEqual(len(summary.diagnostics), 257)
        self.assertEqual(
            summary.diagnostics[-1].code,
            CaptureDiagnosticCode.DIAGNOSTICS_TRUNCATED,
        )

    def test_rejected_record_diagnostic_count_is_bounded(self) -> None:
        record = self._record("capture_start", 0)
        record.update({f"unexpected_{index}": index for index in range(300)})
        items, summary = self._read_payload(
            self._encode_records(
                [record, self._record("capture_end", 1, complete=True)]
            )
        )
        first = items[0]
        self.assertIsInstance(first, InvalidCaptureRecord)
        self.assertEqual(len(first.diagnostics), 257)
        self.assertIn(
            CaptureDiagnosticCode.DIAGNOSTICS_TRUNCATED,
            {diagnostic.code for diagnostic in first.diagnostics},
        )
        self.assertEqual(len(summary.diagnostics), 257)
        self.assertFalse(summary.complete)

    def test_capture_schema_exactly_models_each_record_kind(self) -> None:
        schema = json.loads(CAPTURE_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        records = [
            self._record("capture_start", 0),
            self._record("session_start", 1, session="s"),
            self._message(
                2,
                "connection",
                self._json_bytes(self.messages["connection"]),
                session="s",
            ),
            self._record(
                "drop",
                3,
                session="s",
                drop_count=1,
                drop_reason="synthetic_drop",
            ),
            self._record("session_end", 4, session="s"),
            self._record("capture_end", 5, complete=True),
        ]
        for record in records:
            with self.subTest(kind=record["kind"]):
                self.assertEqual(list(validator.iter_errors(record)), [])

        capture_start = self._record("capture_start", 0)
        capture_start["complete"] = True
        self.assertTrue(list(validator.iter_errors(capture_start)))
        runtime_items, _ = self._read_payload(
            self._encode_records(
                [
                    capture_start,
                    self._record("capture_end", 1, complete=True),
                ]
            )
        )
        self.assertIsInstance(runtime_items[0], InvalidCaptureRecord)

    def test_envelope_scalar_bounds_are_enforced(self) -> None:
        schema = json.loads(CAPTURE_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        cases = []
        sequence = self._record("capture_start", 0)
        sequence["sequence"] = 1 << 63
        cases.append(sequence)
        cases.append(self._record("capture_start", -1))
        boolean_sequence = self._record("capture_start", 0)
        boolean_sequence["sequence"] = True
        cases.append(boolean_sequence)
        receive_time = self._record("capture_start", 0)
        receive_time["receive_time_ns"] = 1 << 63
        cases.append(receive_time)
        cases.append(self._record("capture_start", 0, receive_time_ns=-1))
        monotonic = self._record("capture_start", 0, monotonic=-1)
        cases.append(monotonic)
        session = self._record("session_start", 0, session="s" * 257)
        cases.append(session)
        cases.append(self._record("session_start", 0, session=""))
        topic = self._message(0, "connection", b"{}", topic="t" * 4097)
        cases.append(topic)
        cases.append(self._message(0, "connection", b"{}", topic=""))
        qos = self._message(0, "connection", b"{}")
        qos["qos"] = 3
        cases.append(qos)
        retained = self._message(0, "connection", b"{}")
        retained["retained"] = 0
        cases.append(retained)
        reason = self._record(
            "drop",
            0,
            session="s",
            drop_count=1,
            drop_reason="r" * 1025,
        )
        cases.append(reason)
        cases.append(
            self._record(
                "drop",
                0,
                session="s",
                drop_count=0,
                drop_reason="synthetic_drop",
            )
        )
        cases.append(
            self._record(
                "drop",
                0,
                session="s",
                drop_count=1,
                drop_reason="",
            )
        )
        complete = self._record("capture_end", 0, complete=True)
        complete["complete"] = 1
        cases.append(complete)
        wrong_schema = self._record("capture_start", 0)
        wrong_schema["schema"] = "unsupported"
        cases.append(wrong_schema)
        missing_topic = self._message(0, "connection", b"{}")
        del missing_topic["topic"]
        cases.append(missing_topic)
        for record in cases:
            with self.subTest(fields=tuple(record)):
                self.assertTrue(list(validator.iter_errors(record)))
                item = self._first_item(self._encode_records([record]))
                self.assertIsInstance(item, InvalidCaptureRecord)
                self.assertIn(
                    CaptureDiagnosticCode.ENVELOPE_VIOLATION,
                    {diagnostic.code for diagnostic in item.diagnostics},
                )

    def test_drop_count_signed_64_bit_boundary_matches_schema(self) -> None:
        schema = json.loads(CAPTURE_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        maximum = (1 << 63) - 1
        cases = ((1, True), (maximum, True), (0, False), (-1, False), (1 << 63, False))
        for drop_count, expected in cases:
            with self.subTest(drop_count=drop_count):
                record = self._record(
                    "drop",
                    0,
                    session="s",
                    drop_count=drop_count,
                    drop_reason="synthetic_drop",
                )
                schema_valid = not list(validator.iter_errors(record))
                items, _ = self._read_payload(self._encode_records([record]))
                item = items[0]
                runtime_valid = isinstance(item, CaptureDropRecord)
                self.assertIs(schema_valid, expected)
                self.assertIs(runtime_valid, expected)

        for drop_count in (1, maximum):
            with self.subTest(accepted_drop_count=drop_count):
                records = [
                    self._record("capture_start", 0),
                    self._record("session_start", 1, session="s"),
                    self._record(
                        "drop",
                        2,
                        session="s",
                        drop_count=drop_count,
                        drop_reason="synthetic_drop",
                    ),
                    self._record("session_end", 3, session="s"),
                    self._record("capture_end", 4, complete=True),
                ]
                items, summary = self._read_payload(
                    self._encode_records(records)
                )
                self.assertEqual(items[2].drop_count, drop_count)
                self.assertTrue(items[2].capture_accepted)
                self.assertTrue(summary.complete)

        hostile_number = b"9" * (MAX_JSON_NUMBER_CHARACTERS + 1)
        raw = (
            b'{"schema":"mekai.capture_record/0.1","kind":"drop",'
            b'"sequence":0,"receive_time_ns":0,"collector_session_id":"s",'
            b'"drop_count":'
            + hostile_number
            + b',"drop_reason":"synthetic_drop"}\n'
        )
        item = self._first_item(raw)
        self.assertIsInstance(item, InvalidCaptureRecord)
        self.assertEqual(
            item.diagnostics[0].code, CaptureDiagnosticCode.RESOURCE_LIMIT
        )
        self.assertNotIn(hostile_number[:64].decode("ascii"), str(item.diagnostics))

    def test_envelope_string_and_time_boundaries_are_accepted(self) -> None:
        maximum = (1 << 63) - 1
        session = "s" * 256
        records = [
            self._record("capture_start", 0),
            self._record("session_start", 1, session=session),
            self._message(
                2,
                "connection",
                self._json_bytes(self.messages["connection"]),
                session=session,
                topic="t" * 4096,
            ),
            self._record(
                "drop",
                3,
                session=session,
                drop_count=1,
                drop_reason="r" * 1024,
            ),
            self._record("session_end", 4, session=session),
            self._record("capture_end", 5, complete=True),
        ]
        for record in records:
            record["receive_time_ns"] = maximum
            record["receive_monotonic_ns"] = maximum
        schema = json.loads(CAPTURE_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for record in records:
            self.assertEqual(list(validator.iter_errors(record)), [])
        items, summary = self._read_payload(self._encode_records(records))
        self.assertTrue(all(item.capture_accepted for item in items))
        self.assertTrue(summary.complete)

    def _capture_with_message(
        self, family: str, payload: bytes
    ) -> list[dict[str, object]]:
        return [
            self._record("capture_start", 0),
            self._record("session_start", 1, session="session-a"),
            self._message(2, family, payload, session="session-a"),
            self._record("session_end", 3, session="session-a"),
            self._record("capture_end", 4, complete=True),
        ]

    def _record(
        self,
        kind: str,
        sequence: int,
        *,
        receive_time_ns: int | None = None,
        monotonic: int | None = None,
        session: str | None = None,
        drop_count: int | None = None,
        drop_reason: str | None = None,
        complete: bool | None = None,
    ) -> dict[str, object]:
        record: dict[str, object] = {
            "schema": CAPTURE_SCHEMA_ID,
            "kind": kind,
            "sequence": sequence,
            "receive_time_ns": (
                sequence * 1_000
                if receive_time_ns is None
                else receive_time_ns
            ),
        }
        if monotonic is not None:
            record["receive_monotonic_ns"] = monotonic
        if session is not None:
            record["collector_session_id"] = session
        if drop_count is not None:
            record["drop_count"] = drop_count
        if drop_reason is not None:
            record["drop_reason"] = drop_reason
        if complete is not None:
            record["complete"] = complete
        return record

    def _message(
        self,
        sequence: int,
        family: str,
        payload: bytes,
        *,
        session: str = "session-a",
        topic: str = "site/vda/message",
        monotonic: int | None = None,
    ) -> dict[str, object]:
        record = self._record(
            "message", sequence, session=session, monotonic=monotonic
        )
        record.update(
            {
                "message_family": family,
                "topic": topic,
                "qos": 0,
                "retained": False,
                "duplicate": False,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
            }
        )
        return record

    def _first_item(self, payload: bytes) -> InvalidCaptureRecord:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, payload)
            with CaptureReader(path, "synthetic-capture") as reader:
                item = next(reader)
        self.assertIsInstance(item, InvalidCaptureRecord)
        return item

    def _read_payload(
        self,
        payload: bytes,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> tuple[tuple[object, ...], object]:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, payload)
            return self._read(path, max_message_bytes=max_message_bytes)

    def _read(
        self,
        path: Path,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> tuple[tuple[object, ...], object]:
        with CaptureReader(
            path,
            "synthetic-capture",
            max_message_bytes=max_message_bytes,
        ) as reader:
            items = tuple(reader)
            summary = reader.summary
        return items, summary

    @staticmethod
    def _encode_records(
        records: list[dict[str, object]], *, final_newline: bool = True
    ) -> bytes:
        payload = b"\n".join(
            json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            for record in records
        )
        return payload + (b"\n" if final_newline else b"")

    @staticmethod
    def _json_bytes(value: object) -> bytes:
        return json.dumps(
            value, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    @staticmethod
    def _write(
        directory: str,
        payload: bytes,
        *,
        name: str = "synthetic-capture.jsonl",
    ) -> Path:
        path = Path(directory) / name
        path.write_bytes(payload)
        return path


if __name__ == "__main__":
    unittest.main()
