import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from mekai_open.input_fingerprint import (
    InputChangedError,
    InputFingerprintError,
    fingerprint_regular_file,
    fingerprint_ros_bag_files,
    open_verified_regular_file,
    verify_unchanged,
)


class FingerprintTests(unittest.TestCase):
    def test_regular_file_is_sha256_of_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.jsonl"
            payload = b'{"exact":"bytes"}\n\x00'
            path.write_bytes(payload)
            fingerprint = fingerprint_regular_file(path)
            self.assertEqual(
                fingerprint.sha256, hashlib.sha256(payload).hexdigest()
            )
            serialized = fingerprint.to_dict()
            entry = serialized["entries"][0]
            self.assertEqual(entry["relative_path"], "capture.jsonl")
            self.assertNotIn("absolute_path", entry)
            self.assertNotIn("stat_signature", entry)
            self.assertNotIn(str(path.parent), str(serialized))
            verify_unchanged(fingerprint)

    def test_regular_file_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.jsonl"
            target.write_text("data", encoding="utf-8")
            link = root / "link.jsonl"
            link.symlink_to(target)
            with self.assertRaises(InputFingerprintError):
                fingerprint_regular_file(link)

    def test_regular_file_mutation_is_input_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.jsonl"
            path.write_text("before", encoding="utf-8")
            fingerprint = fingerprint_regular_file(path)
            path.write_text("after", encoding="utf-8")
            with self.assertRaisesRegex(InputChangedError, "INPUT_CHANGED"):
                verify_unchanged(fingerprint)

    def test_open_descriptor_matches_fingerprinted_file_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.jsonl"
            path.write_bytes(b"exact")
            fingerprint = fingerprint_regular_file(path)
            with open_verified_regular_file(fingerprint) as stream:
                self.assertEqual(stream.readline(), b"exact")

    def test_replacement_before_descriptor_open_is_input_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "capture.jsonl"
            replacement = root / "replacement.jsonl"
            path.write_bytes(b"before")
            fingerprint = fingerprint_regular_file(path)
            replacement.write_bytes(b"after")
            os.replace(replacement, path)
            with self.assertRaisesRegex(InputChangedError, "INPUT_CHANGED"):
                open_verified_regular_file(fingerprint)

    def test_regular_file_disappearance_is_input_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.jsonl"
            path.write_text("before", encoding="utf-8")
            fingerprint = fingerprint_regular_file(path)
            path.unlink()
            with self.assertRaisesRegex(InputChangedError, "INPUT_CHANGED"):
                verify_unchanged(fingerprint)

    def test_ros_bag_digest_is_deterministic_and_order_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata.yaml"
            first = root / "bag_0.db3"
            second = root / "bag_1.db3"
            metadata.write_text(
                "relative_file_paths:\n- bag_0.db3\n- bag_1.db3\n"
            )
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            one = fingerprint_ros_bag_files(
                metadata, ("bag_1.db3", "bag_0.db3")
            )
            two = fingerprint_ros_bag_files(
                metadata, ("bag_0.db3", "bag_1.db3")
            )
            self.assertEqual(one.sha256, two.sha256)
            self.assertEqual(
                [item.relative_path for item in one.entries],
                ["metadata.yaml", "bag_0.db3", "bag_1.db3"],
            )
            verify_unchanged(one)

    def test_ros_bag_storage_mutation_is_input_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata.yaml"
            storage = root / "bag.mcap"
            metadata.write_text("relative_file_paths:\n- bag.mcap\n")
            storage.write_bytes(b"before")
            fingerprint = fingerprint_ros_bag_files(metadata, ("bag.mcap",))
            storage.write_bytes(b"after")
            with self.assertRaisesRegex(InputChangedError, "INPUT_CHANGED"):
                verify_unchanged(fingerprint)

    def test_ros_bag_rejects_symlinked_storage_and_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = root / "metadata.yaml"
            target = root / "target.mcap"
            link = root / "bag.mcap"
            metadata.write_text("relative_file_paths:\n- bag.mcap\n")
            target.write_bytes(b"payload")
            link.symlink_to(target)
            with self.assertRaises(InputFingerprintError):
                fingerprint_ros_bag_files(metadata, ("bag.mcap",))
            with self.assertRaises(InputFingerprintError):
                fingerprint_ros_bag_files(metadata, ("../outside.mcap",))


if __name__ == "__main__":
    unittest.main()
