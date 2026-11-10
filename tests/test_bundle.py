"""Synthetic local I/O/CLI checks; all generated files live in temporary dirs.

MESHDRAW_TEST_TMP optionally selects a writable temp root in restricted runners.
The application itself never spawns processes; subprocess is only a CLI test.
"""

import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from meshdraw_core import core, bundle

try:
    from .test_core import GOLDEN_RF, independent_json, make_request
except ImportError:
    from test_core import GOLDEN_RF, independent_json, make_request


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="meshdraw-tests-", dir=os.environ.get("MESHDRAW_TEST_TMP") or None)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.input = self.root / "synthetic-input.json"
        self.output = self.root / "bundle"
        self.write_input(make_request())

    def write_input(self, request, path=None):
        target = self.input if path is None else path
        target.write_bytes(json.dumps(request, indent=2).encode("ascii"))
        return target

    def create(self, request=None, output=None):
        if request is not None:
            self.write_input(request)
        destination = self.output if output is None else output
        return bundle.create_bundle(self.input, destination)

    def read_manifest(self):
        return json.loads((self.output / "manifest.json").read_bytes())

    def write_manifest(self, manifest):
        (self.output / "manifest.json").write_bytes(independent_json(manifest))

    def update_file_metadata(self, name, data):
        (self.output / name).write_bytes(data)
        manifest = self.read_manifest()
        manifest["files"][name] = {
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        self.write_manifest(manifest)

    def assert_bundle_error(self, action, status=None, code=None):
        with self.assertRaises(bundle.BundleError) as caught:
            action()
        if status is not None:
            self.assertEqual(caught.exception.status, status)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        self.assertNotIn(str(self.root), str(caught.exception))
        return caught.exception

    def cli(self, *arguments):
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(PROJECT_ROOT)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-B", "-m", "meshdraw_core", *map(str, arguments)],
            cwd=self.root, env=environment, capture_output=True, text=True,
            encoding="utf-8", timeout=30, check=False)
        self.assertEqual(completed.stderr, "")
        self.assertNotIn(str(self.root), completed.stdout)
        return completed.returncode, json.loads(completed.stdout)

    def test_create_manifest_and_repeat_independently(self):
        report = self.create()
        self.assertEqual(report["status"], "BUNDLE_CREATED")
        self.assertEqual(report["winner_ticket"], "0042")
        self.assertEqual(set(path.name for path in self.output.iterdir()),
                         {"request.json", "result.json", "manifest.json"})
        manifest_raw = (self.output / "manifest.json").read_bytes()
        manifest = self.read_manifest()
        self.assertEqual(manifest["schema_version"], "meshdraw-bundle-v0.2")
        self.assertEqual(report["manifest_sha256"], hashlib.sha256(manifest_raw).hexdigest())
        for name in ("request.json", "result.json"):
            raw = (self.output / name).read_bytes()
            self.assertEqual(manifest["files"][name],
                             {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertEqual(json.loads((self.output / "result.json").read_bytes())["rf"]["sha256"], GOLDEN_RF)
        replay = bundle.replay_bundle(self.output)
        self.assertEqual((replay["status"], replay["replay_match"], replay["plan_match"]),
                         ("REPLAY_MATCH", True, "UNANCHORED"))
        self.assertEqual(bundle.replay_bundle(self.output, report["plan_sha256"].upper())["plan_match"], "MATCH")

    def test_existing_output_refuses_overwrite_and_preserves_every_byte(self):
        self.create()
        before = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.assert_bundle_error(lambda: self.create(), "TECHNICAL_ERROR", "OUTPUT_EXISTS")
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.output.iterdir()})

    def test_changed_file_with_stale_manifest_is_detected(self):
        self.create()
        target = self.output / "request.json"
        old = target.read_bytes()
        changed = old.replace(b'"rssi": "-100"', b'"rssi": "-101"', 1)
        self.assertNotEqual(old, changed)
        self.assertEqual(len(old), len(changed))
        target.write_bytes(changed)
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "FILE_HASH_MISMATCH")

    def test_truncated_file_and_updated_wrong_result_are_detected(self):
        self.create()
        result = json.loads((self.output / "result.json").read_bytes())
        result["mapping"]["ticket"] = "0007"
        self.update_file_metadata("result.json", independent_json(result))
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "RESULT_MISMATCH")
        (self.output / "result.json").write_bytes(b"{}")
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "FILE_SIZE_MISMATCH")

    def test_result_boolean_is_not_accepted_as_integer(self):
        self.create()
        result = json.loads((self.output / "result.json").read_bytes())
        self.assertEqual(result["mapping"]["index"], 1)
        result["mapping"]["index"] = True
        self.update_file_metadata("result.json", independent_json(result))
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "RESULT_MISMATCH")

    def test_recomputed_replacement_has_no_authenticity_without_external_anchor(self):
        original = self.create()
        request = make_request()
        request["tickets"] = ["111", "222", "333"]
        second = self.root / "replacement"
        self.create(request, second)
        self.assertEqual(bundle.replay_bundle(second)["plan_match"], "UNANCHORED")
        anchored = bundle.replay_bundle(second, original["plan_sha256"])
        self.assertEqual((anchored["status"], anchored["replay_match"], anchored["plan_match"]),
                         ("REPLAY_FAILED", True, "MISMATCH"))
        self.assertEqual(anchored["code"], "PLAN_HASH_MISMATCH")

    def test_same_plan_replacement_of_observations_cannot_be_proven_old(self):
        """A plan anchor cannot authenticate which later observations existed."""
        original = self.create()
        request = make_request()
        request["observations"][1]["rssi"] = "-101"
        second = self.root / "changed-observations"
        replacement = self.create(request, second)
        self.assertEqual(original["plan_sha256"], replacement["plan_sha256"])
        self.assertNotEqual(original["input_sha256"], replacement["input_sha256"])
        self.assertNotEqual(original["winner_ticket"], replacement["winner_ticket"])
        replay = bundle.replay_bundle(second, original["plan_sha256"])
        self.assertEqual((replay["replay_match"], replay["plan_match"]), (True, "MATCH"))
        # This is the explicit limit, not evidence that the original was genuine:
        # neither package contains an independent observation-time/fullness proof.

    def test_full_request_hash_is_checked_separately_from_file_hash(self):
        self.create()
        request = json.loads((self.output / "request.json").read_bytes())
        request["observations"][-1]["rssi"] = "-91"
        self.update_file_metadata("request.json", independent_json(request))
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "MANIFEST_INPUT_HASH_MISMATCH")

    def test_missing_and_extra_entries_are_rejected(self):
        self.create()
        extra = self.output / "INCOMPLETE"
        extra.write_text("synthetic marker", encoding="ascii")
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "UNEXPECTED_BUNDLE_ENTRY")
        extra.unlink()
        (self.output / "result.json").unlink()
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "INCOMPLETE_BUNDLE")

    def test_manifest_paths_cannot_escape_allowlist(self):
        self.create()
        original = self.read_manifest()
        outside = self.root / "outside.json"
        outside.write_bytes(b"synthetic-sentinel")
        forbidden = ["../outside.json", "nested/request.json", "..\\outside.json",
                     "/outside.json", "C:\\synthetic-outside.json",
                     "\\\\synthetic-host\\share\\file.json", "request.json/../outside.json"]
        for filename in forbidden:
            with self.subTest(filename=filename):
                manifest = deepcopy(original)
                metadata = manifest["files"].pop("request.json")
                manifest["files"][filename] = metadata
                self.write_manifest(manifest)
                with patch.object(bundle, "_read_regular", wraps=bundle._read_regular) as reader:
                    self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                             "REPLAY_FAILED", "INVALID_MANIFEST_FILES")
                self.assertEqual([call.args[0].name for call in reader.call_args_list], ["manifest.json"])
                self.assertEqual(outside.read_bytes(), b"synthetic-sentinel")

    def test_symlink_or_reparse_is_detected_before_open(self):
        self.create()
        # Actual links may require Windows developer mode. Verify the mandatory
        # metadata guard without requiring administrator rights or creating one.
        fake_reparse = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
        fake_symlink = SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
        self.assertTrue(bundle._is_link_or_reparse(fake_reparse))
        self.assertTrue(bundle._is_link_or_reparse(fake_symlink))
        with patch.object(bundle, "_is_link_or_reparse", return_value=True), \
                patch.object(bundle.os, "open", side_effect=AssertionError("must not open link")):
            self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                     "REPLAY_FAILED", "LINK_OR_REPARSE_POINT")

    def test_real_symlink_target_is_not_followed_when_platform_allows(self):
        self.create()
        target = self.root / "synthetic-link-target.json"
        target.write_bytes((self.output / "result.json").read_bytes())
        link = self.output / "result.json"
        link.unlink()
        try:
            link.symlink_to(target)
        except OSError:
            # The metadata guard has a separate mandatory test on Windows.
            self.skipTest("Creating real symlinks is unavailable for this user")
        before = target.read_bytes()
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "LINK_OR_REPARSE_POINT")
        self.assertEqual(target.read_bytes(), before)

    def test_bundle_caps_request_result_manifest_and_structural_depth(self):
        self.input.write_bytes(b" " * (2 * 1024 * 1024 + 1))
        self.assert_bundle_error(lambda: self.create(), "INVALID_INPUT", "FILE_TOO_LARGE")
        self.assertFalse(self.output.exists())
        self.write_input(make_request())
        self.create()
        original_manifest = (self.output / "manifest.json").read_bytes()
        (self.output / "manifest.json").write_bytes(b" " * (64 * 1024 + 1))
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output), "REPLAY_FAILED", "FILE_TOO_LARGE")
        (self.output / "manifest.json").write_bytes(original_manifest)
        (self.output / "result.json").write_bytes(b" " * (4 * 1024 * 1024 + 1))
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output), "REPLAY_FAILED", "FILE_TOO_LARGE")

    def test_manifest_and_result_json_reject_duplicate_keys_and_float(self):
        self.create()
        original = (self.output / "manifest.json").read_bytes()
        for invalid in (b'{"x":1,"x":2}', b'{"x":1.5}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(invalid=invalid):
                (self.output / "manifest.json").write_bytes(invalid)
                self.assert_bundle_error(lambda: bundle.replay_bundle(self.output), "REPLAY_FAILED")
        (self.output / "manifest.json").write_bytes(original)
        self.update_file_metadata("result.json", b'{"x":1,"x":2}')
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output),
                                 "REPLAY_FAILED", "DUPLICATE_JSON_KEY")

    def test_envelope_depth_numeric_length_and_ascii_are_bounded(self):
        self.create()
        for invalid in (
            b'{"x":' + b'[' * 40 + b'0' + b']' * 40 + b'}',
            b'{"x":' + b'9' * 21 + b'}',
            '{"x":"я"}'.encode("utf-8"),
        ):
            with self.subTest(invalid=invalid[:35]):
                (self.output / "manifest.json").write_bytes(invalid)
                self.assert_bundle_error(lambda: bundle.replay_bundle(self.output), "REPLAY_FAILED")

    def test_failed_write_keeps_explicit_incomplete_package(self):
        real_write = bundle._write_exclusive

        def fail_result(path, data, field):
            if path.name == "result.json":
                raise bundle.BundleError("TECHNICAL_ERROR", "SYNTHETIC_WRITE_FAILURE", field)
            return real_write(path, data, field)

        with patch.object(bundle, "_write_exclusive", side_effect=fail_result):
            self.assert_bundle_error(lambda: self.create(), "TECHNICAL_ERROR", "SYNTHETIC_WRITE_FAILURE")
        self.assertTrue((self.output / "INCOMPLETE").exists())
        self.assertFalse((self.output / "result.json").exists())
        self.assert_bundle_error(lambda: bundle.replay_bundle(self.output), "REPLAY_FAILED")

    def test_no_draw_is_reproducible_not_technical_failure(self):
        request = make_request()
        request["rules"]["min_rows"] = 6
        self.assertEqual(self.create(request)["draw_status"], "NO_DRAW")
        replay = bundle.replay_bundle(self.output)
        self.assertEqual((replay["status"], replay["draw_status"], replay["winner_ticket"]),
                         ("REPLAY_MATCH", "NO_DRAW", None))

    def test_network_modules_are_absent_and_runtime_network_is_blocked(self):
        forbidden = {"socket", "urllib", "http", "requests", "aiohttp", "subprocess", "ftplib"}
        for path in (PROJECT_ROOT / "meshdraw_core").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
            for node in ast.walk(tree):
                modules = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                           else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
                self.assertFalse(any(module.split(".")[0] in forbidden for module in modules), path.name)
        with patch.object(socket, "socket", side_effect=AssertionError("network prohibited")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS prohibited")), \
                patch.object(subprocess, "Popen", side_effect=AssertionError("process prohibited")), \
                patch.object(os, "system", side_effect=AssertionError("process prohibited")):
            self.create()
            self.assertEqual(bundle.replay_bundle(self.output)["status"], "REPLAY_MATCH")

    def test_cli_from_empty_cwd_with_explicit_paths_and_repeat_process(self):
        code, plan = self.cli("plan-hash", "--input", self.input)
        self.assertEqual((code, plan["status"]), (0, "PLAN_HASH"))
        code, created = self.cli("draw", "--input", self.input, "--output", self.output)
        self.assertEqual((code, created["draw_status"], created["winner_ticket"]), (0, "DRAW", "0042"))
        code, replay = self.cli("replay", "--bundle", self.output,
                                "--expected-plan-hash", plan["plan_sha256"])
        self.assertEqual((code, replay["plan_match"]), (0, "MATCH"))
        second = self.root / "second-process-bundle"
        code, _ = self.cli("draw", "--input", self.input, "--output", second)
        self.assertEqual(code, 0)
        for name in ("request.json", "result.json", "manifest.json"):
            self.assertEqual((self.output / name).read_bytes(), (second / name).read_bytes())
        self.assertFalse((self.root / "__pycache__").exists())

    def test_cli_exit_codes_no_overwrite_mismatch_and_invalid_input(self):
        code, _ = self.cli("draw", "--input", self.input, "--output", self.output)
        self.assertEqual(code, 0)
        before = (self.output / "manifest.json").read_bytes()
        code, error = self.cli("draw", "--input", self.input, "--output", self.output)
        self.assertEqual((code, error["code"]), (6, "OUTPUT_EXISTS"))
        self.assertEqual((self.output / "manifest.json").read_bytes(), before)
        code, mismatch = self.cli("replay", "--bundle", self.output, "--expected-plan-hash", "0" * 64)
        self.assertEqual((code, mismatch["plan_match"]), (5, "MISMATCH"))
        code, error = self.cli("draw")
        self.assertEqual((code, error["code"]), (2, "INVALID_CLI_ARGUMENTS"))
        self.input.write_bytes(b'{"x":1,"x":2}')
        code, error = self.cli("draw", "--input", self.input, "--output", self.root / "bad-json")
        self.assertEqual((code, error["code"]), (2, "DUPLICATE_JSON_KEY"))

    def test_cli_conflict_no_draw_and_missing_file_codes(self):
        request = make_request()
        request["observations"][1]["record_id"] = request["observations"][0]["record_id"]
        self.write_input(request)
        code, error = self.cli("draw", "--input", self.input, "--output", self.output)
        self.assertEqual((code, error["status"]), (3, "CONFLICTING_INPUT"))
        request = make_request()
        request["rules"]["min_rows"] = 6
        self.write_input(request)
        code, result = self.cli("draw", "--input", self.input, "--output", self.output)
        self.assertEqual((code, result["draw_status"]), (4, "NO_DRAW"))
        code, error = self.cli("plan-hash", "--input", self.root / "not-present.json")
        self.assertEqual((code, error["status"]), (6, "TECHNICAL_ERROR"))

    def test_cli_bad_arguments_never_echo_paths_or_arbitrary_values(self):
        sentinel = "SYNTHETIC-ARGUMENT-NEVER-ECHO"
        code, error = self.cli("draw", "--input", self.input, "--unexpected", sentinel)
        self.assertEqual((code, error["code"]), (2, "INVALID_CLI_ARGUMENTS"))
        self.assertNotIn(sentinel, json.dumps(error))


if __name__ == "__main__":
    unittest.main()
