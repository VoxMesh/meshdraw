"""Small offline CLI. Exit 4 means a valid, packaged NO_DRAW outcome."""

import argparse
import json
import sys

from .bundle import BundleError, _read_request, create_bundle, replay_bundle
from .core import InputError, plan_hash


class _SafeParser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse messages can echo arbitrary command-line values and paths.
        raise BundleError("INVALID_INPUT", "INVALID_CLI_ARGUMENTS", "arguments")


def _parser():
    parser = _SafeParser(description="Offline MeshDraw research calculation")
    commands = parser.add_subparsers(dest="command", required=True)
    draw = commands.add_parser("draw", help="Calculate one request into a new local bundle")
    draw.add_argument("--input", required=True)
    draw.add_argument("--output", required=True)
    plan = commands.add_parser("plan-hash", help="Calculate the canonical plan hash")
    plan.add_argument("--input", required=True)
    replay = commands.add_parser("replay", help="Recompute a local bundle")
    replay.add_argument("--bundle", required=True)
    replay.add_argument("--expected-plan-hash")
    return parser


def _error_report(error):
    report = {"status": error.status, "code": error.code}
    if error.field is not None:
        report["field"] = error.field
    return report


def main(argv=None):
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "draw":
            report = create_bundle(arguments.input, arguments.output)
            code = 4 if report["draw_status"] == "NO_DRAW" else 0
        elif arguments.command == "plan-hash":
            _, request = _read_request(arguments.input)
            report = {"status": "PLAN_HASH", "plan_sha256": plan_hash(request)}
            code = 0
        else:
            report = replay_bundle(arguments.bundle, arguments.expected_plan_hash)
            code = 0 if report["status"] == "REPLAY_MATCH" else 5
    except (InputError, BundleError) as error:
        report = _error_report(error)
        code = {
            "INVALID_INPUT": 2,
            "CONFLICTING_INPUT": 3,
            "REPLAY_FAILED": 5,
            "TECHNICAL_ERROR": 6,
        }.get(error.status, 6)
    except OSError:
        # Do not print filenames, credentials, or source contents from exceptions.
        report, code = {"status": "TECHNICAL_ERROR", "code": "LOCAL_IO_ERROR"}, 6
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
