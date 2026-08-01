"""Deterministic input identity and mutation detection."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable

_CHUNK_BYTES = 1024 * 1024
_ROS_BAG_DOMAIN = b"mekai-rosbag-input-v1\0"


class InputFingerprintError(ValueError):
    """Invalid or unsafe input."""


class InputChangedError(RuntimeError):
    """Input bytes or file identity changed during analysis."""

    code = "INPUT_CHANGED"


@dataclass(frozen=True, slots=True)
class FileEntrySnapshot:
    """Content identity plus local-only guards for one input entry.

    ``absolute_path`` and ``stat_signature`` are intentionally omitted from
    serialized fingerprints. They are meaningful only within the process and
    host that opened the input.
    """

    relative_path: str
    absolute_path: str
    sha256: str
    size_bytes: int
    stat_signature: tuple[int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class InputFingerprint:
    """Content digest and host-local snapshots for one logical input."""

    kind: str
    sha256: str
    entries: tuple[FileEntrySnapshot, ...]

    def to_dict(self) -> dict[str, object]:
        """Return the portable traceability and mutation-detection digest.

        The serialized form is not a promise that another host can reopen the
        source. Local absolute paths and file-stat guards remain in memory.
        """

        return {
            "schema": "mekai.input_fingerprint/0.1",
            "kind": self.kind,
            "sha256": self.sha256,
            "entries": [
                {
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                }
                for item in self.entries
            ],
        }


def fingerprint_regular_file(path: str | os.PathLike[str]) -> InputFingerprint:
    """Fingerprint one regular, non-symlink file from its exact bytes."""

    source = Path(path)
    entry = _snapshot_file(source, source.name)
    return InputFingerprint("regular_file", entry.sha256, (entry,))


def open_verified_regular_file(fingerprint: InputFingerprint) -> BinaryIO:
    """Open the exact regular file represented by a fresh fingerprint."""

    if fingerprint.kind != "regular_file" or len(fingerprint.entries) != 1:
        raise InputFingerprintError(
            "fingerprint does not describe exactly one regular file"
        )
    entry = fingerprint.entries[0]
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(entry.absolute_path, flags)
    except OSError:
        raise InputChangedError(
            "INPUT_CHANGED: fingerprinted input cannot be opened safely"
        ) from None

    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_signature(opened) != entry.stat_signature
        ):
            raise InputChangedError(
                "INPUT_CHANGED: opened input does not match its fingerprint"
            )
        return os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise


def fingerprint_ros_bag_files(
    metadata_yaml: str | os.PathLike[str],
    referenced_storage_files: Iterable[str | os.PathLike[str]],
) -> InputFingerprint:
    """Fingerprint metadata plus an explicit, caller-validated storage list.

    This function does not parse ``metadata.yaml``. The ROS adapter must derive
    and validate the complete storage-file list before calling it.
    """

    metadata = Path(metadata_yaml)
    if metadata.name != "metadata.yaml":
        raise InputFingerprintError(
            "ROS bag metadata file must be named metadata.yaml"
        )
    bag_root = metadata.parent
    _reject_target_symlink(bag_root)
    if not bag_root.is_dir():
        raise InputFingerprintError("ROS bag root is not a directory")

    paths: dict[str, Path] = {"metadata.yaml": metadata}
    for raw_reference in referenced_storage_files:
        raw = os.fspath(raw_reference)
        pure = PurePosixPath(raw)
        if pure.is_absolute() or not pure.parts or any(
            part in ("", ".", "..") for part in pure.parts
        ):
            raise InputFingerprintError(f"unsafe ROS storage path: {raw!r}")
        relative = pure.as_posix()
        if relative == "metadata.yaml" or relative in paths:
            raise InputFingerprintError(f"duplicate ROS bag path: {relative}")
        candidate = bag_root.joinpath(*pure.parts)
        _reject_relative_symlinks(bag_root, pure)
        paths[relative] = candidate

    if len(paths) == 1:
        raise InputFingerprintError("ROS bag has no referenced storage files")

    entries = tuple(
        _snapshot_file(paths[relative], relative)
        for relative in sorted(
            paths, key=lambda item: (item != "metadata.yaml", item)
        )
    )
    digest = hashlib.sha256()
    digest.update(_ROS_BAG_DOMAIN)
    for entry in entries:
        name = entry.relative_path.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(entry.size_bytes.to_bytes(16, "big"))
        digest.update(bytes.fromhex(entry.sha256))
    return InputFingerprint("ros_bag", digest.hexdigest(), entries)


def verify_unchanged(fingerprint: InputFingerprint) -> None:
    """Re-fingerprint an input and raise ``InputChangedError`` on mutation."""

    try:
        if fingerprint.kind == "regular_file":
            current = fingerprint_regular_file(fingerprint.entries[0].absolute_path)
        elif fingerprint.kind == "ros_bag":
            metadata = fingerprint.entries[0].absolute_path
            references = tuple(
                item.relative_path for item in fingerprint.entries[1:]
            )
            current = fingerprint_ros_bag_files(metadata, references)
        else:
            raise InputFingerprintError(
                f"unsupported fingerprint kind: {fingerprint.kind}"
            )
    except InputChangedError:
        raise
    except InputFingerprintError as exc:
        raise InputChangedError(
            "INPUT_CHANGED: input became unavailable or unsafe during analysis"
        ) from exc

    if (
        current.sha256 != fingerprint.sha256
        or current.entries != fingerprint.entries
    ):
        raise InputChangedError("INPUT_CHANGED: input changed during analysis")


def _snapshot_file(path: Path, relative_path: str) -> FileEntrySnapshot:
    """Hash a regular file while checking identity before and after reading."""

    _reject_target_symlink(path)
    try:
        before_path = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise InputChangedError(
            f"INPUT_CHANGED: input disappeared: {path}"
        ) from exc
    if not stat.S_ISREG(before_path.st_mode):
        raise InputFingerprintError(f"input is not a regular file: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InputFingerprintError(f"cannot safely open input: {path}") from exc

    digest = hashlib.sha256()
    try:
        before_fd = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, _CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        after_fd = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    try:
        after_path = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise InputChangedError(
            f"INPUT_CHANGED: input disappeared: {path}"
        ) from exc

    signatures = (
        _stat_signature(before_path),
        _stat_signature(before_fd),
        _stat_signature(after_fd),
        _stat_signature(after_path),
    )
    if len(set(signatures)) != 1:
        raise InputChangedError(
            f"INPUT_CHANGED: input mutated while hashing: {path}"
        )
    signature = signatures[0]
    return FileEntrySnapshot(
        relative_path=relative_path,
        absolute_path=str(path.absolute()),
        sha256=digest.hexdigest(),
        size_bytes=before_fd.st_size,
        stat_signature=signature,
    )


def _stat_signature(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return the filesystem identity fields used for mutation detection."""

    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _reject_target_symlink(path: Path) -> None:
    """Reject a missing path or a final path component that is a symlink."""

    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise InputFingerprintError(f"input does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise InputFingerprintError(f"symlink inputs are rejected: {path}")


def _reject_relative_symlinks(root: Path, relative: PurePosixPath) -> None:
    """Reject symlinks in every component beneath a trusted root."""

    current = root
    for part in relative.parts:
        current = current / part
        _reject_target_symlink(current)
