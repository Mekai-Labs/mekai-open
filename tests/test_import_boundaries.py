import ast
import json
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SOURCE_ROOT = ROOT / "src" / "mekai_open"
ROS_ADAPTER_MODULES = ("mekai_open.adapters.ros",)


def _production_modules() -> tuple[str, ...]:
    modules: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        relative = path.relative_to(SOURCE_ROOT)
        parts = list(relative.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        modules.append(".".join(("mekai_open", *parts)).rstrip("."))
    return tuple(dict.fromkeys(modules))


class ImportBoundaryTests(unittest.TestCase):
    def test_ros_independent_modules_import_without_ros(self) -> None:
        modules = _production_modules()
        self.assertTrue(modules)
        importable_modules = tuple(
            module
            for module in modules
            if module != "mekai_open.__main__"
            and not any(
                module == prefix or module.startswith(f"{prefix}.")
                for prefix in ROS_ADAPTER_MODULES
            )
        )
        script = textwrap.dedent(
            f"""
            import importlib
            import importlib.abc
            import sys

            blocked_roots = {{"rclpy", "rosbag2_py", "rosbags"}}

            class BlockRos(importlib.abc.MetaPathFinder):
                def find_spec(self, fullname, path=None, target=None):
                    if fullname.split(".", 1)[0] in blocked_roots:
                        raise ModuleNotFoundError(
                            f"ROS import blocked by package-boundary test: {{fullname}}"
                        )
                    return None

            sys.meta_path.insert(0, BlockRos())
            for module_name in {json.dumps(importable_modules)}:
                importlib.import_module(module_name)
            """
        )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def test_no_dynamic_execution_or_publish_calls(self) -> None:
        violations: list[str] = []
        for path in SOURCE_ROOT.rglob("*.py"):
            tree = ast.parse(
                path.read_text(encoding="utf-8"), filename=str(path)
            )
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if isinstance(node.func, ast.Name) and node.func.id in {
                    "eval",
                    "exec",
                }:
                    violations.append(
                        f"{path.relative_to(ROOT)} calls {node.func.id}"
                    )
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr == "publish"
                ):
                    violations.append(f"{path.relative_to(ROOT)} calls publish")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
