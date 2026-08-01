"""Validate portable source identifiers shared by internal contracts."""

from __future__ import annotations

import re

SOURCE_ID_MAX_CHARACTERS = 128
SOURCE_ID_PATTERN = rf"[A-Za-z0-9._-]{{1,{SOURCE_ID_MAX_CHARACTERS}}}"

_SOURCE_ID = re.compile(rf"^(?:{SOURCE_ID_PATTERN})$")
_RESERVED_SOURCE_IDS = frozenset({".", ".."})


def validate_source_id(source_id: object) -> str:
    """Return one valid portable source ID or raise ``ValueError`` safely."""

    if (
        not isinstance(source_id, str)
        or source_id in _RESERVED_SOURCE_IDS
        or _SOURCE_ID.fullmatch(source_id) is None
    ):
        raise ValueError(
            "source_id must contain 1-128 ASCII letters, digits, dots, "
            "underscores, or hyphens and cannot be '.' or '..'"
        )
    return source_id
