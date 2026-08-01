"""Bounded strict JSON decoding and Unicode-scalar safety."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

MAX_JSON_NESTING_DEPTH = 64
MAX_JSON_STRUCTURAL_SEPARATORS = 250_000
MAX_JSON_NUMBER_CHARACTERS = 4_300

_MAX_DIAGNOSTICS = 256
_MAX_EXPLANATION_CHARACTERS = 256
_MAX_POINTER_CHARACTERS = 512
_MAX_POINTER_SEGMENT_CHARACTERS = 96


class StrictJsonDiagnosticCode(StrEnum):
    """Classify one failure produced by the shared strict JSON decoder."""

    INVALID_UTF8 = "INVALID_UTF8"
    INVALID_UNICODE = "INVALID_UNICODE"
    MALFORMED_JSON = "MALFORMED_JSON"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    NON_FINITE_NUMBER = "NON_FINITE_NUMBER"
    NESTING_TOO_DEEP = "NESTING_TOO_DEEP"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    DIAGNOSTICS_TRUNCATED = "DIAGNOSTICS_TRUNCATED"


@dataclass(frozen=True, slots=True)
class StrictJsonDiagnostic:
    """Describe one bounded failure without retaining hostile JSON content."""

    code: StrictJsonDiagnosticCode
    instance_path: str
    explanation: str

    def __post_init__(self) -> None:
        if len(self.explanation) > _MAX_EXPLANATION_CHARACTERS:
            raise ValueError("diagnostic explanation exceeds the safe bound")
        if len(self.instance_path) > _MAX_POINTER_CHARACTERS:
            raise ValueError("instance_path exceeds the safe bound")
        if self.instance_path and not self.instance_path.startswith("/"):
            raise ValueError("instance_path must be an RFC 6901-style pointer")


class StrictJsonDecodingError(ValueError):
    """Carry deterministic bounded diagnostics for invalid JSON bytes."""

    diagnostics: tuple[StrictJsonDiagnostic, ...]

    def __init__(self, diagnostics: Sequence[StrictJsonDiagnostic]) -> None:
        ordered = _ordered_diagnostics(diagnostics)
        if not ordered:
            raise ValueError("at least one strict JSON diagnostic is required")
        self.diagnostics = ordered
        preview = ", ".join(item.code for item in ordered[:8])
        suffix = ", ..." if len(ordered) > 8 else ""
        super().__init__(
            f"JSON input is invalid ({len(ordered)} diagnostic(s): "
            f"{preview}{suffix})"
        )


class _ObjectPairs(list[tuple[str, object]]):
    """Retain every JSON object pair until duplicate detection finishes."""


@dataclass(frozen=True, slots=True)
class _NonFiniteConstant:
    """Retain one forbidden JSON non-finite token for safe classification."""

    token: str


class _JsonNumberLimitError(ValueError):
    """Signal a numeric token longer than the parser-owned limit."""


def contains_invalid_unicode_scalar(value: str) -> bool:
    """Return whether text contains an unpaired Unicode surrogate code point."""

    return any("\ud800" <= character <= "\udfff" for character in value)


def decode_strict_json(payload: bytes) -> object:
    """Decode one exact byte string under the shared bounded JSON policy."""

    if not isinstance(payload, bytes):
        raise TypeError("strict JSON input must be bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.INVALID_UTF8,
                instance_path="",
                explanation="Payload is not strict UTF-8.",
            )
        )
    except MemoryError:
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.RESOURCE_LIMIT,
                instance_path="",
                explanation="UTF-8 decoding exceeded a runtime resource limit.",
            )
        )

    structure_limit = _scan_json_structure(text)
    if structure_limit is StrictJsonDiagnosticCode.NESTING_TOO_DEEP:
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.NESTING_TOO_DEEP,
                instance_path="",
                explanation="JSON nesting exceeds the supported depth of 64.",
            )
        )
    if structure_limit is StrictJsonDiagnosticCode.RESOURCE_LIMIT:
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.RESOURCE_LIMIT,
                instance_path="",
                explanation=(
                    "JSON structural complexity exceeds the supported limit."
                ),
            )
        )

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_capture_object_pairs,
            parse_constant=_capture_non_finite_constant,
            parse_int=_parse_bounded_integer,
            parse_float=_parse_bounded_float,
        )
    except json.JSONDecodeError as error:
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.MALFORMED_JSON,
                instance_path="",
                explanation=(
                    f"Malformed JSON at line {error.lineno}, "
                    f"column {error.colno}."
                ),
            )
        )
    except _JsonNumberLimitError:
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.RESOURCE_LIMIT,
                instance_path="",
                explanation=(
                    "JSON numeric token exceeds the supported character limit."
                ),
            )
        )
    except (MemoryError, OverflowError, RecursionError, ValueError):
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.RESOURCE_LIMIT,
                instance_path="",
                explanation="JSON decoding exceeded a runtime resource limit.",
            )
        )

    diagnostics: list[StrictJsonDiagnostic] = []
    try:
        decoded = _materialize_json(parsed, (), diagnostics)
    except (MemoryError, RecursionError):
        _raise_invalid(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.RESOURCE_LIMIT,
                instance_path="",
                explanation="JSON inspection exceeded a runtime resource limit.",
            )
        )
    if diagnostics:
        raise StrictJsonDecodingError(diagnostics)
    return decoded


def bounded_json_pointer(path: tuple[object, ...]) -> str:
    """Encode a path as a bounded display-safe RFC 6901-style pointer."""

    if not path:
        return ""
    path_digest = hashlib.sha256()
    segments: list[str] = []
    for item in path:
        raw = str(item)
        encoded = raw.encode("utf-8", errors="surrogatepass")
        path_digest.update(len(encoded).to_bytes(8, "big"))
        path_digest.update(encoded)
        segments.append(_bounded_pointer_segment(raw))
    pointer = "/" + "/".join(segments)
    if len(pointer) <= _MAX_POINTER_CHARACTERS:
        return pointer

    marker = _bounded_pointer_segment(
        f"...[path-sha256:{path_digest.hexdigest()[:16]}]"
    )
    prefix: list[str] = []
    for segment in segments:
        candidate = "/" + "/".join((*prefix, segment, marker))
        if len(candidate) > _MAX_POINTER_CHARACTERS:
            break
        prefix.append(segment)
    return "/" + "/".join((*prefix, marker))


def _capture_object_pairs(pairs: list[tuple[str, object]]) -> _ObjectPairs:
    """Preserve raw JSON object pairs for depth-aware duplicate detection."""

    return _ObjectPairs(pairs)


def _capture_non_finite_constant(token: str) -> _NonFiniteConstant:
    """Preserve a non-finite token so inspection can reject it safely."""

    return _NonFiniteConstant(token)


def _parse_bounded_integer(token: str) -> int:
    """Convert an integer token only after enforcing the parser-owned bound."""

    if len(token) > MAX_JSON_NUMBER_CHARACTERS:
        raise _JsonNumberLimitError
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    value = 0
    for start in range(0, len(digits), 9):
        chunk = digits[start : start + 9]
        value = value * (10 ** len(chunk)) + int(chunk, 10)
    return -value if negative else value


def _parse_bounded_float(token: str) -> float:
    """Convert a floating token only after enforcing the parser-owned bound."""

    if len(token) > MAX_JSON_NUMBER_CHARACTERS:
        raise _JsonNumberLimitError
    return float(token)


def _materialize_json(
    value: object,
    path: tuple[str | int, ...],
    diagnostics: list[StrictJsonDiagnostic],
) -> object:
    """Build ordinary JSON values while collecting strict-value failures."""

    if isinstance(value, _NonFiniteConstant):
        _append_diagnostic(
            diagnostics,
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.NON_FINITE_NUMBER,
                instance_path=bounded_json_pointer(path),
                explanation=f"JSON number must be finite; found {value.token}.",
            ),
        )
        return None
    if isinstance(value, _ObjectPairs):
        result: dict[str, object] = {}
        duplicate_keys: set[str] = set()
        for key, item in value:
            if contains_invalid_unicode_scalar(key):
                _append_diagnostic(
                    diagnostics,
                    StrictJsonDiagnostic(
                        code=StrictJsonDiagnosticCode.INVALID_UNICODE,
                        instance_path=bounded_json_pointer((*path, key)),
                        explanation=(
                            "JSON text contains an invalid Unicode scalar value."
                        ),
                    ),
                )
            child = _materialize_json(item, (*path, key), diagnostics)
            if key in result:
                if key not in duplicate_keys:
                    _append_diagnostic(
                        diagnostics,
                        StrictJsonDiagnostic(
                            code=StrictJsonDiagnosticCode.DUPLICATE_KEY,
                            instance_path=bounded_json_pointer((*path, key)),
                            explanation="JSON object contains a duplicate key.",
                        ),
                    )
                    duplicate_keys.add(key)
                continue
            result[key] = child
        return result
    if isinstance(value, list):
        return [
            _materialize_json(item, (*path, index), diagnostics)
            for index, item in enumerate(value)
        ]
    if isinstance(value, str) and contains_invalid_unicode_scalar(value):
        _append_diagnostic(
            diagnostics,
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.INVALID_UNICODE,
                instance_path=bounded_json_pointer(path),
                explanation=(
                    "JSON text contains an invalid Unicode scalar value."
                ),
            ),
        )
        return None
    if isinstance(value, float) and not math.isfinite(value):
        _append_diagnostic(
            diagnostics,
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.NON_FINITE_NUMBER,
                instance_path=bounded_json_pointer(path),
                explanation="JSON number must be finite.",
            ),
        )
        return None
    return value


def _scan_json_structure(text: str) -> StrictJsonDiagnosticCode | None:
    """Find depth or separator resource limits in one string-aware pass."""

    depth = 0
    separators = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING_DEPTH:
                return StrictJsonDiagnosticCode.NESTING_TOO_DEEP
        elif character in "]}":
            depth = max(0, depth - 1)
        elif character in ",:":
            separators += 1
            if separators > MAX_JSON_STRUCTURAL_SEPARATORS:
                return StrictJsonDiagnosticCode.RESOURCE_LIMIT
    return None


def _bounded_pointer_segment(value: str) -> str:
    """Escape one JSON Pointer segment without retaining an unbounded key."""

    source = (
        value[:48]
        if len(value) > _MAX_POINTER_SEGMENT_CHARACTERS
        else value
    )
    safe_value = "".join(
        character
        if character.isprintable() and character not in {"\u2028", "\u2029"}
        else f"\\u{ord(character):04x}"
        for character in source
    )
    if (
        len(value) > _MAX_POINTER_SEGMENT_CHARACTERS
        or len(safe_value) > _MAX_POINTER_SEGMENT_CHARACTERS
    ):
        digest = hashlib.sha256(
            value.encode("utf-8", errors="surrogatepass")
        ).hexdigest()[:16]
        safe_value = f"{safe_value[:48]}...[sha256:{digest}]"
    return safe_value.replace("~", "~0").replace("/", "~1")


def _append_diagnostic(
    diagnostics: list[StrictJsonDiagnostic],
    diagnostic: StrictJsonDiagnostic,
) -> None:
    """Append one diagnostic while enforcing the decoder result bound."""

    if len(diagnostics) < _MAX_DIAGNOSTICS:
        diagnostics.append(diagnostic)
    elif len(diagnostics) == _MAX_DIAGNOSTICS:
        diagnostics.append(
            StrictJsonDiagnostic(
                code=StrictJsonDiagnosticCode.DIAGNOSTICS_TRUNCATED,
                instance_path="",
                explanation=(
                    "Additional diagnostics were omitted at the bounded "
                    "diagnostic limit."
                ),
            )
        )


def _ordered_diagnostics(
    diagnostics: Sequence[StrictJsonDiagnostic],
) -> tuple[StrictJsonDiagnostic, ...]:
    """Return diagnostics in one stable path-and-code order."""

    return tuple(
        sorted(
            diagnostics,
            key=lambda item: (
                item.instance_path,
                item.code.value,
                item.explanation,
            ),
        )
    )


def _raise_invalid(diagnostic: StrictJsonDiagnostic) -> NoReturn:
    """Raise the sole structured exception used by strict JSON decoding."""

    raise StrictJsonDecodingError((diagnostic,))
