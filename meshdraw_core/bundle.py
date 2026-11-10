"""Bounded local bundle I/O; internal hashes are not an authenticity proof."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .core import (
    InputError,
    canonical_bytes,
    evaluate,
    input_hash,
    load_request_json,
    plan_hash,
    validate_request,
)


BUNDLE_VERSION = "meshdraw-bundle-v0.2"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
FILE_LIMITS = {"request.json": MAX_REQUEST_BYTES, "result.json": MAX_RESULT_BYTES}
_BUNDLE_NAMES = frozenset((*FILE_LIMITS, "manifest.json"))
_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_EXPECTED_HEX = re.compile(r"[0-9a-fA-F]{64}\Z", re.ASCII)


class BundleError(Exception):
    """A safe failure description containing no local path or input content."""

    def __init__(self, status: str, code: str, field: str | None = None):
        self.status = status
        self.code = code
        self.field = field
        super().__init__(code)


def _local_path(value, field: str) -> Path:
    try:
        path = Path(value)
        text = os.fspath(path)
    except (TypeError, ValueError):
        raise BundleError("INVALID_INPUT", "INVALID_LOCAL_PATH", field) from None
    # UNC and URL paths could cause network I/O, even through filesystem APIs.
    if text.startswith(("\\\\", "//")) or "://" in text or "\x00" in text:
        raise BundleError("INVALID_INPUT", "NONLOCAL_PATH", field)
    return path


def _is_link_or_reparse(info) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _assert_no_links(path: Path, field: str, status: str = "REPLAY_FAILED") -> None:
    """Check every existing component, including Windows junctions/reparse points."""
    absolute = path.absolute()
    for component in (*reversed(absolute.parents), absolute):
        try:
            info = component.lstat()
        except OSError:
            raise BundleError("TECHNICAL_ERROR", "PATH_UNAVAILABLE", field) from None
        if _is_link_or_reparse(info):
            raise BundleError(status, "LINK_OR_REPARSE_POINT", field)


def _read_regular(
    path: Path, limit: int, field: str, status: str = "REPLAY_FAILED"
) -> bytes:
    """Read at most limit+1 bytes and reject files substituted before opening."""
    _assert_no_links(path, field, status)
    descriptor = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise BundleError(status, "NOT_REGULAR_FILE", field)
        if before.st_size > limit:
            raise BundleError(status, "FILE_TOO_LARGE", field)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_or_reparse(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise BundleError(status, "FILE_CHANGED_DURING_READ", field)
        if opened.st_size > limit:
            raise BundleError(status, "FILE_TOO_LARGE", field)
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise BundleError(status, "FILE_TOO_LARGE", field)
        after = path.lstat()
        if _is_link_or_reparse(after) or (after.st_dev, after.st_ino) != (
            before.st_dev,
            before.st_ino,
        ):
            raise BundleError(status, "FILE_CHANGED_DURING_READ", field)
        return data
    except OSError:
        raise BundleError("TECHNICAL_ERROR", "FILE_READ_FAILED", field) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _reject_json_number(_value):
    raise BundleError("REPLAY_FAILED", "NONINTEGER_JSON_NUMBER", "bundle")


def _json_integer(value):
    if len(value) > 20:
        raise BundleError("REPLAY_FAILED", "JSON_INTEGER_LENGTH", "bundle")
    return int(value)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BundleError("REPLAY_FAILED", "DUPLICATE_JSON_KEY", "bundle")
        result[key] = value
    return result


def _load_json(data: bytes, field: str):
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_int=_json_integer,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
        # Apply the same bounded ASCII tree, depth and node rules as the core.
        canonical_bytes(value)
        return value
    except InputError as error:
        raise BundleError("REPLAY_FAILED", error.code, field) from None
    except (UnicodeError, ValueError, RecursionError):
        raise BundleError("REPLAY_FAILED", "INVALID_JSON", field) from None


def _read_request(input_path):
    path = _local_path(input_path, "input")
    raw = _read_regular(path, MAX_REQUEST_BYTES, "input", "INVALID_INPUT")
    request = load_request_json(raw)
    validate_request(request)
    return raw, request


def _write_exclusive(path: Path, data: bytes, field: str) -> None:
    """Write only a new file; the caller owns the newly created directory."""
    descriptor = None
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            if handle.write(data) != len(data):
                raise BundleError("TECHNICAL_ERROR", "PARTIAL_WRITE", field)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise BundleError("TECHNICAL_ERROR", "FILE_WRITE_FAILED", field) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _result_summary(result) -> dict:
    mapping = result["mapping"]
    return {
        "draw_status": result["status"],
        "reason": result["reason"],
        "winner_ticket": mapping["ticket"] if mapping is not None else None,
    }


def create_bundle(input_path, output_dir) -> dict:
    """Evaluate one explicit local request and create a new, exclusive bundle."""
    raw, request = _read_request(input_path)
    result = evaluate(request)
    result_bytes = canonical_bytes(result)
    if len(result_bytes) > MAX_RESULT_BYTES:
        raise BundleError("TECHNICAL_ERROR", "RESULT_TOO_LARGE", "result")
    contents = {"request.json": raw, "result.json": result_bytes}
    manifest = {
        "schema_version": BUNDLE_VERSION,
        "files": {
            name: {"bytes": len(data), "sha256": _digest(data)}
            for name, data in contents.items()
        },
        "plan_sha256": plan_hash(request),
        "input_sha256": input_hash(request),
    }
    manifest_bytes = canonical_bytes(manifest)
    destination = _local_path(output_dir, "output")
    _assert_no_links(destination.parent, "output", "INVALID_INPUT")
    try:
        destination.mkdir(exist_ok=False)
    except FileExistsError:
        raise BundleError("TECHNICAL_ERROR", "OUTPUT_EXISTS", "output") from None
    except OSError:
        raise BundleError("TECHNICAL_ERROR", "OUTPUT_CREATE_FAILED", "output") from None

    # A failed write leaves this marker behind, and replay rejects the directory.
    marker = destination / "INCOMPLETE"
    _write_exclusive(marker, b"incomplete\n", "output")
    for name, data in contents.items():
        _write_exclusive(destination / name, data, name)
    _write_exclusive(destination / "manifest.json", manifest_bytes, "manifest")
    try:
        marker.unlink()
    except OSError:
        raise BundleError("TECHNICAL_ERROR", "PACKAGE_INCOMPLETE", "output") from None
    return {
        "status": "BUNDLE_CREATED",
        **_result_summary(result),
        "plan_sha256": manifest["plan_sha256"],
        "input_sha256": manifest["input_sha256"],
        "manifest_sha256": _digest(manifest_bytes),
    }


def _validate_manifest(manifest) -> None:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "files", "plan_sha256", "input_sha256"
    }:
        raise BundleError("REPLAY_FAILED", "INVALID_MANIFEST", "manifest")
    if manifest["schema_version"] != BUNDLE_VERSION:
        raise BundleError("REPLAY_FAILED", "UNKNOWN_BUNDLE_VERSION", "manifest")
    for name in ("plan_sha256", "input_sha256"):
        value = manifest[name]
        if not isinstance(value, str) or _HEX.fullmatch(value) is None:
            raise BundleError("REPLAY_FAILED", "INVALID_MANIFEST_HASH", name)
    files = manifest["files"]
    # Exact names reject absolute, drive/UNC, traversal and mixed-separator paths.
    if not isinstance(files, dict) or set(files) != set(FILE_LIMITS):
        raise BundleError("REPLAY_FAILED", "INVALID_MANIFEST_FILES", "manifest")
    for name, entry in files.items():
        if not isinstance(entry, dict) or set(entry) != {"bytes", "sha256"}:
            raise BundleError("REPLAY_FAILED", "INVALID_FILE_METADATA", name)
        size, digest = entry["bytes"], entry["sha256"]
        if type(size) is not int or not 0 <= size <= FILE_LIMITS[name]:
            raise BundleError("REPLAY_FAILED", "INVALID_FILE_SIZE", name)
        if not isinstance(digest, str) or _HEX.fullmatch(digest) is None:
            raise BundleError("REPLAY_FAILED", "INVALID_FILE_HASH", name)


def _validate_directory(directory: Path) -> None:
    _assert_no_links(directory, "bundle")
    try:
        if not stat.S_ISDIR(directory.lstat().st_mode):
            raise BundleError("REPLAY_FAILED", "NOT_BUNDLE_DIRECTORY", "bundle")
        names = set()
        with os.scandir(directory) as entries:
            for entry in entries:
                names.add(entry.name)
                if entry.name not in _BUNDLE_NAMES or len(names) > 3:
                    raise BundleError("REPLAY_FAILED", "UNEXPECTED_BUNDLE_ENTRY", "bundle")
        if names != _BUNDLE_NAMES:
            raise BundleError("REPLAY_FAILED", "INCOMPLETE_BUNDLE", "bundle")
    except OSError:
        raise BundleError("TECHNICAL_ERROR", "DIRECTORY_READ_FAILED", "bundle") from None


def replay_bundle(bundle_dir, expected_plan_hash: str | None = None) -> dict:
    """Recompute all stages; an optional external plan hash anchors only the plan."""
    if expected_plan_hash is not None:
        if (
            not isinstance(expected_plan_hash, str)
            or _EXPECTED_HEX.fullmatch(expected_plan_hash) is None
        ):
            raise BundleError("INVALID_INPUT", "INVALID_EXPECTED_PLAN_HASH", "expected_plan_hash")
        expected_plan_hash = expected_plan_hash.lower()
    directory = _local_path(bundle_dir, "bundle")
    _validate_directory(directory)
    manifest_bytes = _read_regular(directory / "manifest.json", MAX_MANIFEST_BYTES, "manifest")
    manifest = _load_json(manifest_bytes, "manifest")
    _validate_manifest(manifest)
    contents = {}
    for name, limit in FILE_LIMITS.items():
        data = _read_regular(directory / name, limit, name)
        entry = manifest["files"][name]
        if len(data) != entry["bytes"]:
            raise BundleError("REPLAY_FAILED", "FILE_SIZE_MISMATCH", name)
        if _digest(data) != entry["sha256"]:
            raise BundleError("REPLAY_FAILED", "FILE_HASH_MISMATCH", name)
        contents[name] = data
    request = load_request_json(contents["request.json"])
    validate_request(request)
    actual_plan_hash, actual_input_hash = plan_hash(request), input_hash(request)
    if actual_plan_hash != manifest["plan_sha256"]:
        raise BundleError("REPLAY_FAILED", "MANIFEST_PLAN_HASH_MISMATCH", "plan_sha256")
    if actual_input_hash != manifest["input_sha256"]:
        raise BundleError("REPLAY_FAILED", "MANIFEST_INPUT_HASH_MISMATCH", "input_sha256")
    recorded = _load_json(contents["result.json"], "result")
    computed = evaluate(request)
    # Canonical bytes preserve distinctions such as True versus 1 in JSON.
    if canonical_bytes(recorded) != canonical_bytes(computed):
        raise BundleError("REPLAY_FAILED", "RESULT_MISMATCH", "result")
    plan_match = (
        "UNANCHORED" if expected_plan_hash is None
        else "MATCH" if expected_plan_hash == actual_plan_hash else "MISMATCH"
    )
    report = {
        "status": "REPLAY_MATCH" if plan_match != "MISMATCH" else "REPLAY_FAILED",
        "replay_match": True,
        "plan_match": plan_match,
        "plan_sha256": actual_plan_hash,
        "input_sha256": actual_input_hash,
        **_result_summary(computed),
    }
    if plan_match == "MISMATCH":
        report["code"] = "PLAN_HASH_MISMATCH"
    return report
