"""Command-line access to implemented Mekai Open interfaces."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from .function_registry import get_function_spec, list_function_specs


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser for implemented CLI surfaces."""

    parser = argparse.ArgumentParser(
        prog="mekai-open",
        description="Inspect Mekai Open built-in function specifications.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    specs = subparsers.add_parser("specs", help="inspect built-in specifications")
    spec_commands = specs.add_subparsers(
        dest="specs_command", required=True
    )

    list_parser = spec_commands.add_parser("list", help="list built-in specs")
    list_parser.add_argument("--json", action="store_true", dest="as_json")

    describe = spec_commands.add_parser(
        "describe", help="show one built-in specification"
    )
    describe.add_argument("qualified_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return its process exit status."""

    args = _parser().parse_args(argv)
    if args.specs_command == "list":
        specs = list_function_specs()
        if args.as_json:
            print(
                json.dumps(
                    [item.to_dict() for item in specs],
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for item in specs:
                print(f"{item.qualified_id}\t{item.basis.value}")
        return 0

    try:
        spec = get_function_spec(args.qualified_id)
    except KeyError as exc:
        _parser().error(str(exc))
    print(json.dumps(spec.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
    return 0
