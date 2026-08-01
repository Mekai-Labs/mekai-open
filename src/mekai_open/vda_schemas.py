"""Verify official schemas and validate bounded VDA 5050 payload bytes."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn

from jsonschema.exceptions import SchemaError, ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import validator_for
from referencing import Registry
from referencing.exceptions import NoSuchResource, Unresolvable

from .json_safety import (
    MAX_JSON_NESTING_DEPTH,
    MAX_JSON_NUMBER_CHARACTERS,
    MAX_JSON_STRUCTURAL_SEPARATORS,
    StrictJsonDecodingError,
    bounded_json_pointer,
    decode_strict_json,
)

VDA_VERSION = "3.0.0"
DEFAULT_MAX_MESSAGE_BYTES = 8 * 1024 * 1024
MAX_MESSAGE_BYTES_CEILING = 64 * 1024 * 1024

_VENDOR_ROOT = Path(__file__).parent / "_vendor" / "vda5050"
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
_MAX_DIAGNOSTICS = 256
_MAX_EXPLANATION_CHARS = 256
_MAX_POINTER_CHARS = 512
_REQUIRED_SCHEMAS = frozenset(
    {
        "connection.schema",
        "instantActions.schema",
        "order.schema",
        "state.schema",
    }
)


type FrozenJsonValue = (
    None
    | bool
    | int
    | float
    | str
    | tuple["FrozenJsonValue", ...]
    | Mapping[str, "FrozenJsonValue"]
)


class VdaMessageFamily(StrEnum):
    """Identify one supported VDA 5050 message schema family."""

    CONNECTION = "connection"
    ORDER = "order"
    INSTANT_ACTIONS = "instantActions"
    STATE = "state"


class ValidationDiagnosticCode(StrEnum):
    """Classify deterministic reasons why untrusted payload bytes are invalid."""

    EMPTY_PAYLOAD = "EMPTY_PAYLOAD"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_UNICODE = "INVALID_UNICODE"
    MALFORMED_JSON = "MALFORMED_JSON"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    NON_FINITE_NUMBER = "NON_FINITE_NUMBER"
    NESTING_TOO_DEEP = "NESTING_TOO_DEEP"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    DIAGNOSTICS_TRUNCATED = "DIAGNOSTICS_TRUNCATED"


@dataclass(frozen=True, slots=True)
class ValidationDiagnostic:
    """Describe one safe, structured payload-validation failure."""

    code: ValidationDiagnosticCode
    instance_path: str
    schema_path: str | None
    explanation: str

    def __post_init__(self) -> None:
        if len(self.explanation) > _MAX_EXPLANATION_CHARS:
            raise ValueError("diagnostic explanation exceeds the safe bound")
        for name, path in (
            ("instance_path", self.instance_path),
            ("schema_path", self.schema_path),
        ):
            if path is None:
                continue
            if len(path) > _MAX_POINTER_CHARS:
                raise ValueError(f"{name} exceeds the safe bound")
            if path and not path.startswith("/"):
                raise ValueError(f"{name} must be an RFC 6901-style pointer")


@dataclass(frozen=True, slots=True)
class ValidatedVdaMessage:
    """Hold one structurally valid message and its exact byte identity."""

    family: VdaMessageFamily
    raw_bytes: bytes
    raw_sha256: str
    decoded: FrozenJsonValue


class VdaPayloadValidationError(ValueError):
    """Carry all bounded diagnostics for one invalid untrusted payload."""

    diagnostics: tuple[ValidationDiagnostic, ...]

    def __init__(
        self, diagnostics: Sequence[ValidationDiagnostic]
    ) -> None:
        ordered = _ordered_diagnostics(diagnostics)
        if not ordered:
            raise ValueError("at least one validation diagnostic is required")
        self.diagnostics = ordered
        preview = ", ".join(item.code for item in ordered[:8])
        suffix = ", ..." if len(ordered) > 8 else ""
        super().__init__(
            f"VDA payload is invalid ({len(ordered)} diagnostic(s): "
            f"{preview}{suffix})"
        )


class UnsupportedMessageFamilyError(ValueError):
    """Report an unsupported caller-supplied message family."""


class InvalidParsingLimitError(ValueError):
    """Report a caller-supplied byte limit outside the supported range."""


class PackagedSchemaError(RuntimeError):
    """Report corrupted or inconsistent packaged VDA schemas."""


def load_schema_manifest() -> dict[str, object]:
    """Load the packaged VDA schema provenance and digest manifest."""

    return _load_schema_manifest(_VENDOR_ROOT)


def verify_vendored_schemas() -> tuple[str, ...]:
    """Return every provenance, presence, digest, or JSON integrity error."""

    return _verify_schema_bundle(_VENDOR_ROOT)


def assert_vendored_schemas() -> None:
    """Raise ``PackagedSchemaError`` when the vendored VDA bundle is invalid."""

    errors = verify_vendored_schemas()
    if errors:
        raise PackagedSchemaError("; ".join(errors))


def validate_vda_payload(
    payload: bytes,
    message_family: str | VdaMessageFamily,
    *,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> ValidatedVdaMessage:
    """Validate exact untrusted bytes against one declared VDA 3.0.0 schema."""

    family = _coerce_message_family(message_family)
    validate_message_byte_limit(max_message_bytes)
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    if not payload:
        _raise_invalid(
            ValidationDiagnostic(
                code=ValidationDiagnosticCode.EMPTY_PAYLOAD,
                instance_path="",
                schema_path=None,
                explanation="Payload must contain JSON bytes.",
            )
        )
    if len(payload) > max_message_bytes:
        _raise_invalid(
            ValidationDiagnostic(
                code=ValidationDiagnosticCode.PAYLOAD_TOO_LARGE,
                instance_path="",
                schema_path=None,
                explanation="Payload exceeds the configured byte limit.",
            )
        )

    try:
        decoded = decode_strict_json(payload)
    except StrictJsonDecodingError as error:
        raise VdaPayloadValidationError(
            tuple(
                ValidationDiagnostic(
                    code=ValidationDiagnosticCode(item.code.value),
                    instance_path=item.instance_path,
                    schema_path=None,
                    explanation=item.explanation,
                )
                for item in error.diagnostics
            )
        ) from None

    diagnostics: list[ValidationDiagnostic] = []
    if isinstance(decoded, dict):
        if "version" in decoded and decoded["version"] != VDA_VERSION:
            _append_diagnostic(
                diagnostics,
                ValidationDiagnostic(
                    code=ValidationDiagnosticCode.VERSION_MISMATCH,
                    instance_path="/version",
                    schema_path=None,
                    explanation='Payload version must equal exactly "3.0.0".',
                )
            )

    validator = _cached_validators()[family]
    try:
        for error in validator.iter_errors(decoded):
            _append_diagnostic(diagnostics, _schema_diagnostic(error))
            if len(diagnostics) > _MAX_DIAGNOSTICS:
                break
    except (MemoryError, RecursionError):
        _raise_invalid(
            ValidationDiagnostic(
                code=ValidationDiagnosticCode.RESOURCE_LIMIT,
                instance_path="",
                schema_path=None,
                explanation="Schema validation exceeded a runtime resource limit.",
            )
        )
    except Unresolvable as error:
        raise PackagedSchemaError(
            "packaged VDA schema contains an unresolvable reference"
        ) from error

    if diagnostics:
        raise VdaPayloadValidationError(diagnostics)

    exact_payload = bytes(payload)
    try:
        frozen = _freeze_json(decoded)
    except (MemoryError, RecursionError):
        _raise_invalid(
            ValidationDiagnostic(
                code=ValidationDiagnosticCode.RESOURCE_LIMIT,
                instance_path="",
                schema_path=None,
                explanation="Message freezing exceeded a runtime resource limit.",
            )
        )
    return ValidatedVdaMessage(
        family=family,
        raw_bytes=exact_payload,
        raw_sha256=hashlib.sha256(exact_payload).hexdigest(),
        decoded=frozen,
    )


def _load_schema_manifest(schema_root: Path) -> dict[str, object]:
    """Load one schema manifest from an explicit internal testable root."""

    payload = _read_packaged_bytes(
        schema_root / "schema_manifest.json",
        "vendored schema manifest",
    )
    try:
        value = decode_strict_json(payload)
    except StrictJsonDecodingError as error:
        raise PackagedSchemaError(
            "vendored schema manifest is not valid JSON"
        ) from error
    if not isinstance(value, dict):
        raise PackagedSchemaError("vendored schema manifest must be an object")
    return value


def _verify_schema_bundle(schema_root: Path) -> tuple[str, ...]:
    """Verify a schema bundle rooted at an explicit internal path."""

    try:
        manifest_path = schema_root / "schema_manifest.json"
        if _is_packaged_symlink(
            manifest_path, "vendored schema manifest"
        ):
            return ("vendored schema manifest is a symlink",)
        manifest = _load_schema_manifest(schema_root)
    except PackagedSchemaError as error:
        return (str(error),)

    errors: list[str] = []
    if manifest.get("vda_version") != VDA_VERSION:
        errors.append("manifest VDA version mismatch")

    source_commit = manifest.get("upstream_schema_source_commit")
    if not isinstance(source_commit, str) or not _GIT_COMMIT.fullmatch(
        source_commit
    ):
        errors.append("manifest upstream schema source commit is invalid")

    schemas = manifest.get("schemas")
    if not isinstance(schemas, dict):
        return tuple(errors + ["manifest schemas must be an object"])
    if set(schemas) != _REQUIRED_SCHEMAS:
        errors.append("manifest schema set does not match supported families")

    for filename, expected in sorted(schemas.items()):
        if not isinstance(filename, str) or not isinstance(expected, str):
            errors.append("manifest schema entry must contain string name/hash")
            continue
        if Path(filename).name != filename:
            errors.append(f"manifest schema path is invalid: {filename}")
            continue
        path = schema_root / filename
        try:
            if _is_packaged_symlink(
                path, f"vendored schema {filename}"
            ):
                errors.append(f"vendored schema is a symlink: {filename}")
                continue
            schema_payload = _read_packaged_bytes(
                path, f"vendored schema {filename}"
            )
        except PackagedSchemaError as error:
            errors.append(str(error))
            continue
        actual = hashlib.sha256(schema_payload).hexdigest()
        if actual != expected:
            errors.append(f"vendored schema hash mismatch: {filename}")
        try:
            json.loads(schema_payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            errors.append(f"vendored schema is not valid JSON: {filename}")

    license_record = manifest.get("license")
    if not isinstance(license_record, dict):
        errors.append("manifest license record must be an object")
    else:
        filename = license_record.get("file")
        expected = license_record.get("sha256")
        if filename != "LICENSE.txt" or not isinstance(expected, str):
            errors.append("manifest license record is invalid")
        else:
            path = schema_root / filename
            try:
                if _is_packaged_symlink(
                    path, "vendored VDA MIT license"
                ):
                    errors.append("vendored license is a symlink")
                else:
                    payload = _read_packaged_bytes(
                        path, "vendored VDA MIT license"
                    )
                    actual = hashlib.sha256(payload).hexdigest()
                    if actual != expected:
                        errors.append("vendored VDA MIT license hash mismatch")
            except PackagedSchemaError as error:
                errors.append(str(error))

    return tuple(errors)


def _compile_validators(schema_root: Path) -> Mapping[VdaMessageFamily, Validator]:
    """Compile verified offline validators from an explicit schema bundle."""

    errors = _verify_schema_bundle(schema_root)
    if errors:
        raise PackagedSchemaError("; ".join(errors))

    validators: dict[VdaMessageFamily, Validator] = {}
    for family in VdaMessageFamily:
        filename = f"{family.value}.schema"
        try:
            schema_payload = _read_packaged_bytes(
                schema_root / filename,
                f"packaged VDA schema {filename}",
            )
            schema = json.loads(schema_payload)
        except PackagedSchemaError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PackagedSchemaError(
                f"packaged VDA schema cannot be loaded: {filename}"
            ) from error
        if not isinstance(schema, dict):
            raise PackagedSchemaError(
                f"packaged VDA schema must be an object: {filename}"
            )
        if schema.get("$schema") != _SCHEMA_DRAFT:
            raise PackagedSchemaError(
                f"packaged VDA schema declares an unsupported draft: {filename}"
            )
        if _contains_nonlocal_reference(schema):
            raise PackagedSchemaError(
                f"packaged VDA schema contains a non-local reference: {filename}"
            )
        validator_class = validator_for(schema)
        try:
            validator_class.check_schema(schema)
        except SchemaError as error:
            raise PackagedSchemaError(
                f"packaged VDA schema is internally invalid: {filename}"
            ) from error
        validators[family] = validator_class(
            schema,
            registry=Registry(retrieve=_deny_remote_schema),
        )
    return MappingProxyType(validators)


@lru_cache(maxsize=1)
def _cached_validators() -> Mapping[VdaMessageFamily, Validator]:
    """Return the process-wide immutable validator mapping."""

    return _compile_validators(_VENDOR_ROOT)


def _deny_remote_schema(uri: str) -> NoReturn:
    """Reject every attempt to retrieve a schema outside the packaged document."""

    raise NoSuchResource(ref=uri)


def _contains_nonlocal_reference(value: object) -> bool:
    """Return whether a schema contains a non-fragment reference."""

    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"$ref", "$dynamicRef"}:
                if not isinstance(item, str) or not item.startswith("#"):
                    return True
            if _contains_nonlocal_reference(item):
                return True
    elif isinstance(value, list):
        return any(_contains_nonlocal_reference(item) for item in value)
    return False


def _coerce_message_family(
    message_family: str | VdaMessageFamily,
) -> VdaMessageFamily:
    """Convert a supported caller value into its message-family enum."""

    if not isinstance(message_family, str):
        raise UnsupportedMessageFamilyError(
            "message_family must name a supported VDA message family"
        )
    try:
        return VdaMessageFamily(message_family)
    except ValueError as error:
        raise UnsupportedMessageFamilyError(
            "unsupported VDA message family; expected connection, order, "
            "instantActions, or state"
        ) from error


def validate_message_byte_limit(max_message_bytes: int) -> None:
    """Reject a configured byte limit outside the documented parser range."""

    if (
        isinstance(max_message_bytes, bool)
        or not isinstance(max_message_bytes, int)
        or max_message_bytes < 1
        or max_message_bytes > MAX_MESSAGE_BYTES_CEILING
    ):
        raise InvalidParsingLimitError(
            "max_message_bytes must be an integer from 1 through 67108864"
        )


def _read_packaged_bytes(path: Path, description: str) -> bytes:
    """Read packaged bytes while replacing filesystem details with safe errors."""

    try:
        return path.read_bytes()
    except FileNotFoundError:
        explanation = f"{description} is missing"
    except OSError:
        explanation = f"{description} cannot be read"
    raise PackagedSchemaError(explanation)


def _is_packaged_symlink(path: Path, description: str) -> bool:
    """Inspect a packaged path without leaking filesystem exception details."""

    try:
        return path.is_symlink()
    except OSError:
        explanation = f"{description} cannot be inspected"
    raise PackagedSchemaError(explanation)


def _schema_diagnostic(error: ValidationError) -> ValidationDiagnostic:
    """Convert one jsonschema error into a bounded payload-safe diagnostic."""

    absolute_path = error.absolute_path
    absolute_schema_path = error.absolute_schema_path
    validator_name = error.validator
    explanations = {
        "required": "Payload is missing a required property.",
        "type": "Payload value has an incorrect JSON type.",
        "enum": "Payload value is not an allowed enum member.",
        "minimum": "Payload number is below the allowed minimum.",
        "maximum": "Payload number is above the allowed maximum.",
        "minItems": "Payload array has too few items.",
        "maxItems": "Payload array has too many items.",
        "pattern": "Payload string does not match the required pattern.",
        "additionalProperties": "Payload contains a disallowed property.",
    }
    explanation = explanations.get(
        validator_name,
        "Payload does not satisfy the official structural schema.",
    )
    return ValidationDiagnostic(
        code=ValidationDiagnosticCode.SCHEMA_VIOLATION,
        instance_path=bounded_json_pointer(tuple(absolute_path)),
        schema_path=bounded_json_pointer(tuple(absolute_schema_path)),
        explanation=explanation,
    )


def _append_diagnostic(
    diagnostics: list[ValidationDiagnostic],
    diagnostic: ValidationDiagnostic,
) -> None:
    """Append one diagnostic while enforcing the process-wide result bound."""

    if len(diagnostics) < _MAX_DIAGNOSTICS:
        diagnostics.append(diagnostic)
    elif len(diagnostics) == _MAX_DIAGNOSTICS:
        diagnostics.append(
            ValidationDiagnostic(
                code=ValidationDiagnosticCode.DIAGNOSTICS_TRUNCATED,
                instance_path="",
                schema_path=None,
                explanation=(
                    "Additional diagnostics were omitted at the bounded "
                    "diagnostic limit."
                ),
            )
        )


def _ordered_diagnostics(
    diagnostics: Sequence[ValidationDiagnostic],
) -> tuple[ValidationDiagnostic, ...]:
    """Return diagnostics in one stable path-and-code order."""

    return tuple(
        sorted(
            diagnostics,
            key=lambda item: (
                item.instance_path,
                item.schema_path or "",
                item.code.value,
                item.explanation,
            ),
        )
    )


def _raise_invalid(diagnostic: ValidationDiagnostic) -> NoReturn:
    """Raise the sole structured exception used for invalid payload bytes."""

    raise VdaPayloadValidationError((diagnostic,))


def _freeze_json(value: object) -> FrozenJsonValue:
    """Recursively freeze a successfully validated decoded JSON value."""

    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(f"unexpected decoded JSON value: {type(value).__name__}")
