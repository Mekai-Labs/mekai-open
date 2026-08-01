import copy
import hashlib
import json
import shutil
import socket
import sys
import traceback
import unittest
import urllib.request
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import mekai_open
from mekai_open.vda_schemas import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_JSON_NESTING_DEPTH,
    MAX_JSON_NUMBER_CHARACTERS,
    MAX_JSON_STRUCTURAL_SEPARATORS,
    MAX_MESSAGE_BYTES_CEILING,
    InvalidParsingLimitError,
    PackagedSchemaError,
    UnsupportedMessageFamilyError,
    ValidationDiagnostic,
    ValidationDiagnosticCode,
    VdaMessageFamily,
    VdaPayloadValidationError,
    _compile_validators,
    _load_schema_manifest,
    _verify_schema_bundle,
    load_schema_manifest,
    validate_vda_payload,
    verify_vendored_schemas,
)


ROOT = Path(__file__).parents[1]
VENDOR_ROOT = ROOT / "src" / "mekai_open" / "_vendor" / "vda5050"
WIRE_FIXTURE = ROOT / "fixtures" / "vda5050" / "order_lifecycle_wire.json"


class VdaPayloadValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture = json.loads(WIRE_FIXTURE.read_text(encoding="utf-8"))
        cls.records = fixture["records"]
        cls.messages = {}
        for record in cls.records:
            cls.messages.setdefault(
                record["message_family"], record["message"]
            )

    def test_valid_message_from_every_supported_family(self) -> None:
        self.assertEqual(
            set(self.messages),
            {family.value for family in VdaMessageFamily},
        )
        for family in VdaMessageFamily:
            with self.subTest(family=family.value):
                raw = self._encode(self.messages[family.value])
                validated = validate_vda_payload(raw, family)
                self.assertEqual(validated.family, family)
                self.assertEqual(validated.decoded["version"], "3.0.0")

    def test_validation_boundary_is_not_a_top_level_public_export(self) -> None:
        self.assertNotIn("validate_vda_payload", mekai_open.__all__)
        self.assertFalse(hasattr(mekai_open, "validate_vda_payload"))

    def test_every_wire_lifecycle_record_passes_complete_schema(self) -> None:
        for record in self.records:
            with self.subTest(
                case=record["case_id"], family=record["message_family"]
            ):
                raw = self._encode(record["message"])
                validated = validate_vda_payload(
                    raw, record["message_family"]
                )
                self.assertEqual(validated.raw_bytes, raw)

    def test_unsupported_caller_arguments_are_not_payload_diagnostics(
        self,
    ) -> None:
        with self.assertRaises(UnsupportedMessageFamilyError):
            validate_vda_payload(b"{}", "visualization")
        with self.assertRaises(UnsupportedMessageFamilyError):
            validate_vda_payload(b"{}", 3)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            validate_vda_payload("{}", "state")  # type: ignore[arg-type]
        for limit in (0, True, MAX_MESSAGE_BYTES_CEILING + 1):
            with self.subTest(limit=limit):
                with self.assertRaises(InvalidParsingLimitError):
                    validate_vda_payload(
                        b"{}", "state", max_message_bytes=limit
                    )
        validate_vda_payload(
            self._encode(self.messages["connection"]),
            "connection",
            max_message_bytes=MAX_MESSAGE_BYTES_CEILING,
        )

    def test_empty_payload(self) -> None:
        diagnostics = self._invalid(b"", "state")
        self.assertEqual(
            [item.code for item in diagnostics],
            [ValidationDiagnosticCode.EMPTY_PAYLOAD],
        )

    def test_invalid_utf8(self) -> None:
        diagnostics = self._invalid(b'{"version":"3.0.0","x":"\xff"}', "state")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.INVALID_UTF8
        )

    def test_malformed_json(self) -> None:
        diagnostics = self._invalid(b'{"version":"3.0.0",}', "state")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.MALFORMED_JSON
        )
        self.assertRegex(
            diagnostics[0].explanation,
            r"^Malformed JSON at line \d+, column \d+\.$",
        )

    def test_duplicate_top_level_key(self) -> None:
        raw = self._connection_with_suffix(b',"headerId":2')
        diagnostics = self._invalid(raw, "connection")
        self.assertEqual(
            diagnostics,
            (
                ValidationDiagnostic(
                    code=ValidationDiagnosticCode.DUPLICATE_KEY,
                    instance_path="/headerId",
                    schema_path=None,
                    explanation="JSON object contains a duplicate key.",
                ),
            ),
        )

    def test_duplicate_nested_key_uses_escaped_json_pointer(self) -> None:
        raw = self._connection_with_suffix(
            b',"extension":{"a/b~c":1,"a/b~c":2}'
        )
        diagnostics = self._invalid(raw, "connection")
        self.assertEqual(diagnostics[0].code, ValidationDiagnosticCode.DUPLICATE_KEY)
        self.assertEqual(
            diagnostics[0].instance_path, "/extension/a~1b~0c"
        )

    def test_control_characters_are_escaped_in_diagnostic_paths(self) -> None:
        raw = self._connection_with_suffix(
            b',"extension":{"line\\nbreak":1,"line\\nbreak":2}'
        )
        diagnostics = self._invalid(raw, "connection")
        self.assertEqual(
            diagnostics[0].instance_path,
            "/extension/line\\u000abreak",
        )
        self.assertNotIn("\n", diagnostics[0].instance_path)

    def test_non_finite_numbers_are_rejected(self) -> None:
        for token in (
            b"NaN",
            b"Infinity",
            b"-Infinity",
            b"1e10000",
            b"-1e10000",
        ):
            with self.subTest(token=token):
                raw = self._connection_with_suffix(b',"extension":' + token)
                diagnostics = self._invalid(raw, "connection")
                self.assertEqual(
                    diagnostics[0].code,
                    ValidationDiagnosticCode.NON_FINITE_NUMBER,
                )
                self.assertEqual(diagnostics[0].instance_path, "/extension")

    def test_integer_token_limit_is_independent_of_interpreter_setting(
        self,
    ) -> None:
        original_limit = sys.get_int_max_str_digits()
        exact = b"1" + b"0" * (MAX_JSON_NUMBER_CHARACTERS - 1)
        over = exact + b"0"
        try:
            sys.set_int_max_str_digits(0)
            with self.assertRaises(VdaPayloadValidationError) as caught:
                validate_vda_payload(
                    self._connection_with_suffix(b',"extension":' + over),
                    "connection",
                )
            sys.set_int_max_str_digits(640)
            validated = validate_vda_payload(
                self._connection_with_suffix(b',"extension":' + exact),
                "connection",
            )
            self.assertIsInstance(validated.decoded["extension"], int)
        finally:
            sys.set_int_max_str_digits(original_limit)

        self.assertEqual(sys.get_int_max_str_digits(), original_limit)
        self.assertEqual(
            caught.exception.diagnostics[0].code,
            ValidationDiagnosticCode.RESOURCE_LIMIT,
        )
        self.assertEqual(
            caught.exception.diagnostics[0].explanation,
            "JSON numeric token exceeds the supported character limit.",
        )
        self.assertNotIn(over.decode("ascii"), str(caught.exception))

    def test_float_token_boundary_is_enforced_before_conversion(self) -> None:
        exact = b"0." + b"1" * (MAX_JSON_NUMBER_CHARACTERS - 2)
        over = exact + b"1"
        validated = validate_vda_payload(
            self._connection_with_suffix(b',"extension":' + exact),
            "connection",
        )
        self.assertIsInstance(validated.decoded["extension"], float)

        diagnostics = self._invalid(
            self._connection_with_suffix(b',"extension":' + over),
            "connection",
        )
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.RESOURCE_LIMIT
        )
        self.assertNotIn(over.decode("ascii"), diagnostics[0].explanation)

    def test_payload_exactly_at_and_above_configured_size_boundary(self) -> None:
        raw = self._encode(self.messages["connection"])
        exact = raw + b" " * 17
        validated = validate_vda_payload(
            exact, "connection", max_message_bytes=len(exact)
        )
        self.assertEqual(validated.raw_bytes, exact)

        diagnostics = self._invalid(
            exact, "connection", max_message_bytes=len(exact) - 1
        )
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.PAYLOAD_TOO_LARGE
        )

    def test_default_eight_mib_boundary_is_enforced_before_decoding(self) -> None:
        raw = self._encode(self.messages["connection"])
        exact = raw + b" " * (DEFAULT_MAX_MESSAGE_BYTES - len(raw))
        validated = validate_vda_payload(exact, "connection")
        self.assertEqual(len(validated.raw_bytes), DEFAULT_MAX_MESSAGE_BYTES)

        diagnostics = self._invalid(exact + b"\xff", "connection")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.PAYLOAD_TOO_LARGE
        )

    def test_nesting_depth_64_is_accepted_and_65_is_rejected(self) -> None:
        base = copy.deepcopy(self.messages["connection"])
        value: object = 0
        for _ in range(MAX_JSON_NESTING_DEPTH - 1):
            value = [value]
        base["extension"] = value
        validate_vda_payload(self._encode(base), "connection")

        base = copy.deepcopy(self.messages["connection"])
        value = 0
        for _ in range(MAX_JSON_NESTING_DEPTH):
            value = [value]
        base["extension"] = value
        diagnostics = self._invalid(self._encode(base), "connection")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.NESTING_TOO_DEEP
        )

    def test_dense_payload_below_structural_limit_remains_valid(self) -> None:
        separator_count = MAX_JSON_STRUCTURAL_SEPARATORS - 100
        array = b"[0" + b",0" * separator_count + b"]"
        validated = validate_vda_payload(
            self._connection_with_suffix(b',"extension":' + array),
            "connection",
        )
        self.assertEqual(
            len(validated.decoded["extension"]), separator_count + 1
        )

    def test_dense_payload_over_structural_limit_skips_json_loads(self) -> None:
        array = (
            b"[0"
            + b",0" * MAX_JSON_STRUCTURAL_SEPARATORS
            + b"]"
        )
        raw = self._connection_with_suffix(b',"extension":' + array)
        with mock.patch("mekai_open.json_safety.json.loads") as loads:
            diagnostics = self._invalid(raw, "connection")
        loads.assert_not_called()
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.RESOURCE_LIMIT
        )
        self.assertEqual(
            diagnostics[0].explanation,
            "JSON structural complexity exceeds the supported limit.",
        )

    def test_structural_characters_inside_a_string_do_not_count(self) -> None:
        message = copy.deepcopy(self.messages["connection"])
        message["extension"] = ",:{}[]" * (
            MAX_JSON_STRUCTURAL_SEPARATORS + 1
        )
        validate_vda_payload(self._encode(message), "connection")

    def test_escaped_quotes_and_backslashes_keep_scanner_inside_string(
        self,
    ) -> None:
        message = copy.deepcopy(self.messages["connection"])
        message["extension"] = (
            '\\"'
            + ",:" * (MAX_JSON_STRUCTURAL_SEPARATORS + 1)
            + "\\\\"
        )
        validate_vda_payload(self._encode(message), "connection")

    def test_unpaired_unicode_surrogates_are_rejected(self) -> None:
        for escaped in (b"\\ud800", b"\\udfff"):
            with self.subTest(escaped=escaped):
                diagnostics = self._invalid(
                    self._connection_with_suffix(
                        b',"extension":"' + escaped + b'"'
                    ),
                    "connection",
                )
                self.assertEqual(
                    diagnostics[0].code,
                    ValidationDiagnosticCode.INVALID_UNICODE,
                )
                self.assertEqual(
                    diagnostics[0].explanation,
                    "JSON text contains an invalid Unicode scalar value.",
                )

    def test_unpaired_surrogate_in_object_key_is_rejected(self) -> None:
        raw = self._connection_with_suffix(
            b',"extension":{"\\ud800":1}'
        )
        diagnostics = self._invalid(raw, "connection")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.INVALID_UNICODE
        )
        self.assertEqual(diagnostics[0].instance_path, "/extension/\\ud800")

    def test_unpaired_surrogate_nested_in_array_mapping_is_rejected(
        self,
    ) -> None:
        raw = self._connection_with_suffix(
            b',"extension":[{"nested":["\\udfff"]}]'
        )
        diagnostics = self._invalid(raw, "connection")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.INVALID_UNICODE
        )
        self.assertEqual(
            diagnostics[0].instance_path, "/extension/0/nested/0"
        )

    def test_valid_surrogate_pair_and_direct_non_bmp_utf8_are_accepted(
        self,
    ) -> None:
        escaped = self._connection_with_suffix(
            b',"extension":"\\ud83d\\ude00"'
        )
        validated = validate_vda_payload(escaped, "connection")
        self.assertEqual(validated.decoded["extension"], "😀")

        message = copy.deepcopy(self.messages["connection"])
        message["extension"] = "😀"
        direct = self._encode(message)
        self.assertIn("😀".encode("utf-8"), direct)
        validated = validate_vda_payload(direct, "connection")
        self.assertEqual(validated.decoded["extension"], "😀")

    def test_missing_required_vda_property(self) -> None:
        message = copy.deepcopy(self.messages["connection"])
        del message["headerId"]
        diagnostics = self._invalid(self._encode(message), "connection")
        self.assertEqual(
            {item.code for item in diagnostics},
            {ValidationDiagnosticCode.SCHEMA_VIOLATION},
        )
        self.assertEqual(diagnostics[0].schema_path, "/required")

    def test_invalid_enum(self) -> None:
        message = copy.deepcopy(self.messages["connection"])
        message["connectionState"] = "CONNECTED"
        diagnostics = self._invalid(self._encode(message), "connection")
        self.assertEqual(diagnostics[0].instance_path, "/connectionState")
        self.assertEqual(
            diagnostics[0].explanation,
            "Payload value is not an allowed enum member.",
        )

    def test_incorrect_property_type(self) -> None:
        message = copy.deepcopy(self.messages["connection"])
        message["headerId"] = "1"
        diagnostics = self._invalid(self._encode(message), "connection")
        self.assertEqual(diagnostics[0].instance_path, "/headerId")
        self.assertEqual(
            diagnostics[0].explanation,
            "Payload value has an incorrect JSON type.",
        )

    def test_version_must_equal_exactly_3_0_0(self) -> None:
        for version in ("2.0.0", "3.0", "3.0.0 ", None):
            with self.subTest(version=version):
                message = copy.deepcopy(self.messages["connection"])
                message["version"] = version
                diagnostics = self._invalid(
                    self._encode(message), "connection"
                )
                self.assertIn(
                    ValidationDiagnosticCode.VERSION_MISMATCH,
                    {item.code for item in diagnostics},
                )

    def test_valid_json_is_checked_against_declared_family(self) -> None:
        raw = self._encode(self.messages["connection"])
        diagnostics = self._invalid(raw, "order")
        self.assertGreater(len(diagnostics), 1)
        self.assertEqual(
            {item.code for item in diagnostics},
            {ValidationDiagnosticCode.SCHEMA_VIOLATION},
        )

    def test_diagnostic_order_and_paths_are_deterministic(self) -> None:
        message = copy.deepcopy(self.messages["state"])
        message["headerId"] = "one"
        message["driving"] = "yes"
        message["safetyState"]["activeEmergencyStop"] = "INVALID"
        raw = self._encode(message)

        first = self._invalid(raw, "state")
        second = self._invalid(raw, "state")
        self.assertEqual(first, second)
        self.assertEqual(
            [item.instance_path for item in first],
            sorted(item.instance_path for item in first),
        )
        self.assertTrue(all(item.schema_path for item in first))

    def test_exact_raw_bytes_sha256_and_unknown_fields_are_preserved(self) -> None:
        message = copy.deepcopy(self.messages["connection"])
        message["vendorExtension"] = {"kept": [1, "two", True]}
        raw = json.dumps(message, indent=2, ensure_ascii=False).encode("utf-8")
        validated = validate_vda_payload(raw, "connection")

        self.assertEqual(validated.raw_bytes, raw)
        self.assertEqual(
            validated.raw_sha256, hashlib.sha256(raw).hexdigest()
        )
        self.assertEqual(
            validated.decoded["vendorExtension"]["kept"],
            (1, "two", True),
        )
        with self.assertRaises(TypeError):
            validated.decoded["version"] = "changed"  # type: ignore[index]

    def test_hostile_value_is_not_copied_into_error_text(self) -> None:
        hostile = "sensitive-value-" * 1000
        message = copy.deepcopy(self.messages["connection"])
        message["headerId"] = hostile
        try:
            validate_vda_payload(self._encode(message), "connection")
        except VdaPayloadValidationError as error:
            self.assertNotIn(hostile, str(error))
            self.assertTrue(
                all(hostile not in item.explanation for item in error.diagnostics)
            )
            self.assertTrue(
                all(len(item.explanation) <= 256 for item in error.diagnostics)
            )
        else:
            self.fail("invalid payload unexpectedly passed validation")

    def test_hostile_duplicate_key_path_is_bounded_and_redacted(self) -> None:
        hostile_key = "sensitive-key-" * 1000
        encoded_key = json.dumps(hostile_key).encode("utf-8")
        raw = self._connection_with_suffix(
            b',"extension":{'
            + encoded_key
            + b":1,"
            + encoded_key
            + b":2}"
        )
        diagnostics = self._invalid(raw, "connection")
        self.assertNotIn(hostile_key, diagnostics[0].instance_path)
        self.assertLessEqual(len(diagnostics[0].instance_path), 512)
        self.assertIn("sha256", diagnostics[0].instance_path)

    def test_parse_diagnostics_are_bounded(self) -> None:
        pairs = []
        for index in range(300):
            pairs.extend((f'"key{index}":1', f'"key{index}":2'))
        raw = self._connection_with_suffix(
            (',"extension":{' + ",".join(pairs) + "}").encode("utf-8")
        )
        diagnostics = self._invalid(raw, "connection")
        self.assertEqual(len(diagnostics), 257)
        self.assertEqual(
            sum(
                item.code is ValidationDiagnosticCode.DIAGNOSTICS_TRUNCATED
                for item in diagnostics
            ),
            1,
        )

    def test_decoder_resource_failure_is_structured(self) -> None:
        raw = self._encode(self.messages["connection"])
        with mock.patch(
            "mekai_open.json_safety.json.loads", side_effect=MemoryError
        ):
            diagnostics = self._invalid(raw, "connection")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.RESOURCE_LIMIT
        )

    def test_freezing_resource_failure_is_structured(self) -> None:
        raw = self._encode(self.messages["connection"])
        with mock.patch(
            "mekai_open.vda_schemas._freeze_json", side_effect=MemoryError
        ):
            diagnostics = self._invalid(raw, "connection")
        self.assertEqual(
            diagnostics[0].code, ValidationDiagnosticCode.RESOURCE_LIMIT
        )

    def test_repeated_validation_does_not_mutate_cached_schemas(self) -> None:
        raw = self._encode(self.messages["order"])
        before = verify_vendored_schemas()
        first = validate_vda_payload(raw, "order")
        second = validate_vda_payload(raw, "order")
        self.assertEqual(first, second)
        self.assertEqual(verify_vendored_schemas(), before)
        self.assertEqual(before, ())

    def test_packaged_schema_corruption_fails_loudly_through_test_seam(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "vda5050"
            shutil.copytree(VENDOR_ROOT, root)
            schema_path = root / "state.schema"
            schema_path.write_bytes(schema_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                PackagedSchemaError, "schema hash mismatch"
            ):
                _compile_validators(root)

    def test_manifest_filesystem_failure_is_normalized(self) -> None:
        with TemporaryDirectory() as directory:
            root = self._copy_vendor(directory)
            manifest_path = root / "schema_manifest.json"
            manifest_path.unlink()
            manifest_path.mkdir()

            self.assertEqual(
                _verify_schema_bundle(root),
                ("vendored schema manifest cannot be read",),
            )
            for operation in (
                lambda: _load_schema_manifest(root),
                lambda: _compile_validators(root),
            ):
                with self.subTest(operation=operation):
                    with self.assertRaises(PackagedSchemaError) as caught:
                        operation()
                    self.assertNotIn(str(root), str(caught.exception))

    def test_schema_filesystem_failure_is_normalized(self) -> None:
        with TemporaryDirectory() as directory:
            root = self._copy_vendor(directory)
            schema_path = root / "state.schema"
            schema_path.unlink()
            schema_path.mkdir()

            errors = _verify_schema_bundle(root)
            self.assertIn(
                "vendored schema state.schema cannot be read", errors
            )
            with self.assertRaises(PackagedSchemaError) as caught:
                _compile_validators(root)
            self.assertNotIn(str(root), str(caught.exception))

    def test_license_filesystem_failure_is_normalized(self) -> None:
        with TemporaryDirectory() as directory:
            root = self._copy_vendor(directory)
            license_path = root / "LICENSE.txt"
            license_path.unlink()
            license_path.mkdir()

            errors = _verify_schema_bundle(root)
            self.assertIn(
                "vendored VDA MIT license cannot be read", errors
            )
            with self.assertRaises(PackagedSchemaError) as caught:
                _compile_validators(root)
            self.assertNotIn(str(root), str(caught.exception))

    def test_public_manifest_load_does_not_leak_permission_error(self) -> None:
        sensitive_detail = "/host/private/schema_manifest.json"
        with mock.patch.object(
            Path,
            "read_bytes",
            side_effect=PermissionError(sensitive_detail),
        ):
            with self.assertRaises(PackagedSchemaError) as caught:
                load_schema_manifest()
            errors = verify_vendored_schemas()
        self.assertEqual(
            str(caught.exception),
            "vendored schema manifest cannot be read",
        )
        self.assertEqual(errors, ("vendored schema manifest cannot be read",))
        self.assertNotIn(sensitive_detail, str(caught.exception))
        self.assertNotIn(
            sensitive_detail,
            "".join(traceback.format_exception(caught.exception)),
        )

    def test_second_schema_read_filesystem_failure_is_normalized(self) -> None:
        with TemporaryDirectory() as directory:
            root = self._copy_vendor(directory)
            original_read_bytes = Path.read_bytes
            connection_reads = 0

            def guarded_read_bytes(path: Path) -> bytes:
                nonlocal connection_reads
                if path.name == "connection.schema":
                    connection_reads += 1
                    if connection_reads == 2:
                        raise PermissionError("/host/private/connection.schema")
                return original_read_bytes(path)

            with mock.patch.object(
                Path, "read_bytes", new=guarded_read_bytes
            ):
                with self.assertRaises(PackagedSchemaError) as caught:
                    _compile_validators(root)

            self.assertEqual(connection_reads, 2)
            self.assertEqual(
                str(caught.exception),
                "packaged VDA schema connection.schema cannot be read",
            )
            self.assertNotIn(str(root), str(caught.exception))
            self.assertNotIn(
                "/host/private/connection.schema",
                "".join(traceback.format_exception(caught.exception)),
            )

    def test_validator_compilation_reads_manifest_once(self) -> None:
        with TemporaryDirectory() as directory:
            root = self._copy_vendor(directory)
            original_read_bytes = Path.read_bytes
            manifest_reads = 0

            def counted_read_bytes(path: Path) -> bytes:
                nonlocal manifest_reads
                if path.name == "schema_manifest.json":
                    manifest_reads += 1
                return original_read_bytes(path)

            with mock.patch.object(
                Path, "read_bytes", new=counted_read_bytes
            ):
                _compile_validators(root)
            self.assertEqual(manifest_reads, 1)

    def test_nonlocal_schema_reference_is_rejected_without_network_access(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory) / "vda5050"
            shutil.copytree(VENDOR_ROOT, root)
            schema_path = root / "connection.schema"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["remote"] = {
                "$ref": "https://example.invalid/schema"
            }
            raw = self._encode(schema)
            schema_path.write_bytes(raw)
            manifest_path = root / "schema_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schemas"]["connection.schema"] = hashlib.sha256(
                raw
            ).hexdigest()
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )

            with (
                mock.patch.object(
                    socket,
                    "create_connection",
                    side_effect=AssertionError("network access attempted"),
                ),
                mock.patch.object(
                    urllib.request,
                    "urlopen",
                    side_effect=AssertionError("network access attempted"),
                ),
                self.assertRaisesRegex(
                    PackagedSchemaError, "non-local reference"
                ),
            ):
                _compile_validators(root)

    def _invalid(
        self,
        payload: bytes,
        family: str,
        *,
        max_message_bytes: int | None = None,
    ) -> tuple[ValidationDiagnostic, ...]:
        kwargs = (
            {}
            if max_message_bytes is None
            else {"max_message_bytes": max_message_bytes}
        )
        with self.assertRaises(VdaPayloadValidationError) as caught:
            validate_vda_payload(payload, family, **kwargs)
        return caught.exception.diagnostics

    def _connection_with_suffix(self, suffix: bytes) -> bytes:
        raw = self._encode(self.messages["connection"])
        self.assertTrue(raw.endswith(b"}"))
        return raw[:-1] + suffix + b"}"

    def _copy_vendor(self, directory: str) -> Path:
        root = Path(directory) / "vda5050"
        shutil.copytree(VENDOR_ROOT, root)
        return root

    @staticmethod
    def _encode(value: object) -> bytes:
        return json.dumps(
            value, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


if __name__ == "__main__":
    unittest.main()
