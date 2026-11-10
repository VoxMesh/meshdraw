"""Verify a saved public package without network access."""
import argparse
import json
import sys

from meshdraw_core.core import InputError
from .archive.math import read
from .verifier import verify_package


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", help="Path to a verification JSON file")
    args = parser.parse_args()
    try:
        result = verify_package(read(args.package))
    except (InputError, OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError):
        print(json.dumps({"status": "INVALID_PACKAGE"}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
