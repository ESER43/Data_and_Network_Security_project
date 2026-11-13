import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from patchguard.config import load_project
from patchguard.errors import PatchGuardError
from patchguard.diffing import _relative_diff_text, correlate, parse_hunks
from patchguard.evaluate import (
    _aggregate,
    _classify_fuzz_finding,
    _failure_matches_site,
    _evaluate_test,
    _load_regression_cases,
    _save_regression_case,
    _write_reproducer,
)
from patchguard.hardening import _nx_stack_from_program_headers


class ExitCodePriorityTests(unittest.TestCase):
    def test_assignment_priority(self):
        # The assignment orders simultaneous codes as 30, 10, 20, 40, 0.
        self.assertEqual(_aggregate([30, 10, 20, 40, 0]), 30)
        self.assertEqual(_aggregate([10, 20]), 10)
        self.assertEqual(_aggregate([20, 40]), 20)
        self.assertEqual(_aggregate([10, 40, 0]), 10)
        self.assertEqual(_aggregate([40, 0]), 40)
        self.assertEqual(_aggregate([0, 0]), 0)


class RegressionCorpusTests(unittest.TestCase):
    def test_confirmed_finding_round_trips_and_validates(self):
        test = {"name": "overflow", "kind": "security", "stdin": "seed"}
        runs = [{"failure": {"kind": "address_sanitizer", "error_type": "heap-buffer-overflow"}}
                for _ in range(3)]
        with tempfile.TemporaryDirectory() as temporary:
            saved = _save_regression_case(
                temporary, "sample-target", test, b"minimized input", "VULN_REMAINS",
                "incomplete-patch", "commit123", runs, runs,
            )
            loaded = _load_regression_cases(temporary, "sample-target")
            self.assertTrue(saved["created"])
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["input"], b"minimized input")
            self.assertEqual(loaded[0]["record"]["stdin_sha256"], hashlib.sha256(b"minimized input").hexdigest())

            record_path = Path(loaded[0]["path"])
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["stdin_sha256"] = "0" * 64
            record_path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(PatchGuardError):
                _load_regression_cases(temporary, "sample-target")

    def test_same_input_is_not_stored_twice(self):
        runs = [{"failure": {"kind": "address_sanitizer", "error_type": "heap-buffer-overflow"}}
                for _ in range(3)]
        with tempfile.TemporaryDirectory() as temporary:
            first = _save_regression_case(
                temporary, "target", {"name": "seed_a", "kind": "security"}, b"same input",
                "VULN_REMAINS", "incomplete-patch", "c1", runs, runs,
            )
            second = _save_regression_case(
                temporary, "target", {"name": "seed_b", "kind": "security"}, b"same input",
                "NEW_ISSUE", "incomplete-patch", "c2", runs, runs,
            )
            stored = list(Path(temporary).rglob("*.json"))

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["path"], second["path"])
        self.assertEqual(len(stored), 1)

    def test_replay_classifies_fixed_and_still_vulnerable_cases(self):
        signature = ["address_sanitizer", "requested"]
        baseline_runs = [{"failure": {"kind": signature[0], "error_type": signature[1]}}
                         for _ in range(3)]
        clean_runs = [{"failure": None, "returncode": 0} for _ in range(3)]
        record = {
            "expected_baseline_signature": [signature, signature, signature],
            "expected_candidate_signature": [signature, signature, signature],
            "stdin_sha256": hashlib.sha256(b"old finding").hexdigest(),
            "source_scenario": "incomplete-patch",
            "source_candidate_revision": "commit123",
        }
        case = {"record": record, "path": "case.json"}
        test = {"name": "stored_case", "kind": "security"}

        for candidate_runs, expected_status in ((clean_runs, "FIXED"),
                                                (baseline_runs, "VULN_REMAINS")):
            def fake_run_many(executable, _test, _data, _target, _repetitions):
                if executable == "baseline":
                    return baseline_runs
                if executable == "candidate":
                    return candidate_runs
                return clean_runs

            with patch("patchguard.evaluate._run_many", side_effect=fake_run_many):
                result = _evaluate_test(
                    test, b"old finding", {"release": "baseline", "instrumented": "baseline"},
                    {"release": "candidate", "instrumented": "candidate"}, {}, {},
                    regression_case=case,
                )
            self.assertEqual(result["status"], expected_status)


class FuzzClassificationTests(unittest.TestCase):
    def test_unstable_baseline_does_not_become_new_issue(self):
        failure_run = {
            "failure": {"kind": "address_sanitizer", "error_type": "heap-buffer-overflow"},
            "stderr": "/tmp/source/main.c:10:3",
        }
        baseline_runs = [failure_run, {"failure": None}, failure_run]
        candidate_runs = [failure_run, failure_run, failure_run]
        diff = {"hunks": [{"path": "main.c", "old_start": 10, "old_count": 1,
                           "new_start": 10, "new_count": 1, "header": "@@ -10 +10 @@"}]}

        classification, _correlation, baseline_state = _classify_fuzz_finding(
            baseline_runs, candidate_runs, diff
        )

        self.assertFalse(baseline_state["stable"])
        self.assertEqual(classification, "INCONCLUSIVE")

    def test_stable_same_site_finding_is_classified_without_source_argument(self):
        failure_run = {
            "failure": {"kind": "address_sanitizer", "error_type": "heap-buffer-overflow"},
            "stderr": "#0 0x123 in main /tmp/source/main.c:10:3",
        }
        baseline_runs = [dict(failure_run) for _ in range(3)]
        candidate_runs = [dict(failure_run) for _ in range(3)]
        diff = {"hunks": [{"path": "main.c", "old_start": 10, "old_count": 1,
                           "new_start": 10, "new_count": 1, "header": "@@ -10 +10 @@ int main(void)"}]}

        classification, _correlation, baseline_state = _classify_fuzz_finding(
            baseline_runs, candidate_runs, diff
        )

        self.assertTrue(baseline_state["stable"])
        self.assertEqual(classification, "VULN_REMAINS")


class DiffCorrelationTests(unittest.TestCase):
    def test_nearby_match_requires_same_function(self):
        diff = {"hunks": [{"path": "main.c", "old_start": 10, "old_count": 2,
                           "new_start": 10, "new_count": 2,
                           "header": "@@ -10,2 +10,2 @@ int main(void)"}]}

        same_function = correlate(
            diff, "", "#0 0x123 in main /tmp/build/main.c:15:3", side="new"
        )
        other_function = correlate(
            diff, "", "#0 0x123 in on_value /tmp/build/main.c:15:3", side="new"
        )

        self.assertEqual(same_function["evidence_level"], "nearby")
        self.assertTrue(same_function["matches"][0]["same_function"])
        self.assertEqual(other_function["evidence_level"], "none")
        self.assertFalse(other_function["related"])


class ConfigValidationTests(unittest.TestCase):
    def _project(self, root, **test_overrides):
        Path(root, "vuln").mkdir(exist_ok=True)
        test = {"name": "sample", "kind": "functional", "stdin": "x", "expected_exit": 0}
        test.update(test_overrides)
        data = {"schema_version": 1, "workspace": ".", "targets": [{
            "name": "target",
            "versions": {"vulnerable": "vuln"},
            "scenarios": [{"name": "scenario", "candidate": "vulnerable"}],
            "tests": [test],
            "build": {"release": ["cc"], "instrumented": ["cc"], "executable": "{build}/t"},
            "timeout_seconds": 3,
        }]}
        path = Path(root) / "project.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_malformed_values_are_config_errors(self):
        cases = ({"expected_exit": "zero"}, {"stdin_base64": "!!!not base64!!!"},
                 {"argv": "not-a-list"}, {"fuzz": "yes"})
        for overrides in cases:
            with tempfile.TemporaryDirectory() as root:
                with self.assertRaises(PatchGuardError):
                    load_project(self._project(root, **overrides))

    def test_valid_configuration_still_loads(self):
        with tempfile.TemporaryDirectory() as root:
            project = load_project(self._project(root))
        self.assertEqual(project["targets"][0]["name"], "target")

    def test_integer_fields_accept_numeric_strings_and_reject_floats(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._project(root)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["schema_version"] = "1"
            data["fuzz_seed"] = "2026"
            data["targets"][0]["fuzz_iterations"] = "3"
            data["targets"][0]["limits"] = {"output_bytes": "4096"}
            data["targets"][0]["tests"][0]["expected_exit"] = "0"
            path.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(load_project(path)["targets"][0]["fuzz_iterations"], "3")

        invalid_fields = (
            ("schema_version", 1.7),
            ("fuzz_seed", 1.7),
            ("target.fuzz_iterations", 1.7),
            ("target.limits", {"output_bytes": 1.7}),
            ("test.expected_exit", 1.7),
        )
        for field, value in invalid_fields:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as root:
                path = self._project(root)
                data = json.loads(path.read_text(encoding="utf-8"))
                if field.startswith("target."):
                    data["targets"][0][field.split(".", 1)[1]] = value
                elif field == "test.expected_exit":
                    data["targets"][0]["tests"][0]["expected_exit"] = value
                else:
                    data[field] = value
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(PatchGuardError):
                    load_project(path)


class MinimizationLocationTests(unittest.TestCase):
    def test_minimization_match_requires_original_file_and_function(self):
        failure = {"kind": "address_sanitizer", "error_type": "heap-buffer-overflow"}
        with tempfile.TemporaryDirectory() as root:
            source = Path(root)
            expected_site = {"file": "src/worker.c", "line": 20, "function": "parse_item"}

            def run(path, function):
                return {"failure": failure,
                        "stderr": f"#0 0x123 in {function} {source / path}:20:3"}

            def locations(_diff, _stdout, stderr):
                function = "parse_item" if "parse_item" in stderr else "different_function"
                file = "src/worker.c" if "worker.c" in stderr else "src/other.c"
                return {"locations": [{"path": str(source / file), "line": 20,
                                        "function": function}]}

            with patch("patchguard.evaluate.correlate", side_effect=locations):
                self.assertTrue(_failure_matches_site(
                    run("src/worker.c", "parse_item"), "address_sanitizer", "heap-buffer-overflow",
                    expected_site, source,
                ))
                self.assertFalse(_failure_matches_site(
                    run("src/worker.c", "different_function"), "address_sanitizer", "heap-buffer-overflow",
                    expected_site, source,
                ))
                self.assertFalse(_failure_matches_site(
                    run("src/other.c", "parse_item"), "address_sanitizer", "heap-buffer-overflow",
                    expected_site, source,
                ))

    def test_reproducer_keeps_input_if_reduced_crash_moves_function(self):
        failure = {"kind": "address_sanitizer", "error_type": "heap-buffer-overflow"}
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            source.mkdir()
            (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            executable = Path(root) / "target"
            executable.write_bytes(b"fake executable")

            def observed_run(executable, test, data, timeout, environment, limits):
                function = "parse_item" if data == b"ab" else "other_function"
                return {"failure": failure,
                        "stderr": f"#0 0x123 in {function} {source / 'main.c'}:20:3"}

            def locations(_diff, _stdout, stderr):
                function = "parse_item" if "parse_item" in stderr else "other_function"
                return {"locations": [{"path": str(source / "main.c"), "line": 20,
                                        "function": function}]}

            reference_runs = [observed_run(executable, {}, b"ab", 3, None, None) for _ in range(3)]
            with patch("patchguard.evaluate.run_program", side_effect=observed_run), \
                    patch("patchguard.evaluate.correlate", side_effect=locations), \
                    patch("patchguard.evaluate.git_revision", return_value=None):
                payload = _write_reproducer(
                    Path(root) / "reproducers", {"name": "site", "kind": "security"}, b"ab",
                    {"timeout_seconds": 3, "build": {}}, source,
                    {"kind": failure["kind"], "error_type": failure["error_type"]}, executable,
                    reference_runs=reference_runs,
                )

        self.assertEqual(payload["minimized_stdin_base64"], "YWI=")
        self.assertEqual(payload["original_crash_site"]["function"], "parse_item")
        self.assertEqual(payload["minimized_crash_site"]["function"], "parse_item")
        self.assertTrue(payload["crash_site_preserved"])


class DiffPathParsingTests(unittest.TestCase):
    def test_no_index_paths_with_spaces_become_source_relative(self):
        diff = ("diff --git a/C:/tmp/Project 1/before/main.c b/C:/tmp/Project 1/after/main.c\n"
                "--- a/C:/tmp/Project 1/before/main.c\t\n"
                "+++ b/C:/tmp/Project 1/after/main.c\t\n"
                "@@ -9 +9 @@ int main(void)\n")

        text = _relative_diff_text(diff, ("C:/tmp/Project 1/before", "C:/tmp/Project 1/after"))
        hunks = parse_hunks(text)

        self.assertEqual(hunks[0]["path"], "main.c")
        self.assertEqual(hunks[0]["old_start"], 9)


class DiffCorrelationDecoratedHeaderTests(unittest.TestCase):
    def test_export_macro_in_header_still_correlates(self):
        diff = {"hunks": [{"path": "cJSON.c", "old_start": 409, "old_count": 1,
                           "new_start": 409, "new_count": 1,
                           "header": "@@ -409 +409 @@ CJSON_PUBLIC(char*) cJSON_SetValuestring(cJSON *object, const char *valuestring)"}]}
        stderr = ("    #0 0x55d0 in cJSON_SetValuestring /tmp/build/cJSON.c:413\n"
                  "    #1 0x55d0 in main /tmp/build/driver.c:33\n")

        evidence = correlate(diff, "", stderr, side="old")

        self.assertTrue(evidence["related"])
        self.assertEqual(evidence["evidence_level"], "nearby")
        self.assertEqual(evidence["matches"][0]["hunk_function"], "cJSON_SetValuestring")


class ElfHardeningParsingTests(unittest.TestCase):
    def test_nx_uses_gnu_stack_permissions(self):
        safe = "GNU_STACK 0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW 0x10"
        executable = "GNU_STACK 0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10"
        self.assertIs(_nx_stack_from_program_headers(safe), True)
        self.assertIs(_nx_stack_from_program_headers(executable), False)
        self.assertIsNone(_nx_stack_from_program_headers("no GNU_STACK header"))


if __name__ == "__main__":
    unittest.main()
