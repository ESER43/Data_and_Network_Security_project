import base64
import hashlib
import io
import json
import platform
import random
import re
import subprocess
import tarfile
import sys
from pathlib import Path

from .config import test_input
from .diffing import correlate, directory_diff, revision_diff
from .errors import BuildError, PatchGuardError
from .fuzz import mutate
from .hardening import compare_hardening, inspect_elf
from .minimize import minimize_bytes
from .process import build_target, run_program


REPEAT_COUNT = 3
# Assignment priority: build/config errors first, then functional regressions,
# then remaining/new security findings, then inconclusive runs, then PASS.
CODE_PRIORITY = (30, 10, 20, 40)
# Minimizing the same input against the same binary is deterministic, and the
# baseline reproducer is regenerated for every scenario of a target (and for the
# candidate of an equivalent patch), so results are memoized per binary/input.
_MINIMIZATION_CACHE = {}


def source_fingerprint(source):
    digest = hashlib.sha256()
    for path in sorted(Path(source).rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        relative = path.relative_to(source).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_revision(source):
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def ref_revision(repository, ref):
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", f"{ref}^{{commit}}"],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def prepare_repository(repository, cache_root):
    repository = Path(repository)
    if repository.is_dir():
        return repository
    cache = Path(cache_root) / "repository-cache"
    if cache.is_dir():
        result = subprocess.run(
            ["git", "-C", str(cache), "fetch", "--quiet", "--force", str(repository),
             "+refs/heads/*:refs/heads/*"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            raise PatchGuardError(f"could not refresh cached Git bundle {repository}: {result.stderr.strip()}")
        return cache
    cache.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--quiet", "--bare", str(repository), str(cache)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        raise PatchGuardError(f"could not load Git bundle {repository}: {result.stderr.strip()}")
    return cache


def extract_ref(repository, ref, revision, root, role):
    destination = Path(root) / "sources" / f"{role}-{revision[:12]}"
    if destination.is_dir():
        return destination
    destination.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "-C", str(repository), "archive", "--format=tar", ref],
        capture_output=True, check=False,
    )
    if result.returncode != 0:
        raise PatchGuardError(f"could not export Git ref {ref!r} from {repository}")
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        members = archive.getmembers()
        for member in members:
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise PatchGuardError(f"unsafe path in Git archive: {member.name}")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise PatchGuardError(f"unsupported entry in Git archive: {member.name}")
        archive.extractall(destination)
    return destination


def _aggregate(codes):
    nonzero = [code for code in codes if code]
    return min(nonzero, key=CODE_PRIORITY.index) if nonzero else 0


def _trim_observation(observation):
    limit = 12000
    for field in ("stdout", "stderr"):
        if len(observation.get(field, "")) >= limit or observation.get("output_truncated"):
            observation[field] = observation[field][:limit] + "\n...[truncated]"
    return observation


def _run_many(executable, test, data, target, repetitions):
    results = []
    for _ in range(repetitions):
        results.append(_trim_observation(run_program(
            executable, test, data, float(target.get("timeout_seconds", 3)),
            target.get("environment"), target.get("limits"),
        )))
    return results


def _failure_state(runs):
    failures = [run.get("failure") for run in runs]
    signatures = [(failure.get("kind"), failure.get("error_type")) if failure else None for failure in failures]
    if not signatures or len(set(signatures)) != 1 or signatures[0] is None:
        return {"stable": False, "kind": None, "error_type": None}
    kind, error_type = signatures[0]
    return {"stable": kind is not None, "kind": kind, "error_type": error_type}


def _failure_signature(runs):
    return [
        [run["failure"].get("kind"), run["failure"].get("error_type")]
        if run.get("failure") else None
        for run in runs
    ]


def _safe_component(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value)) or "unnamed"


def _load_regression_cases(corpus_root, target_name):
    target_root = Path(corpus_root) / _safe_component(target_name)
    if not target_root.exists():
        return []
    cases = []
    for path in sorted(target_root.rglob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            data = base64.b64decode(record["stdin_base64"], validate=True)
            test = dict(record["test_definition"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PatchGuardError(f"invalid regression-corpus case {path}: {exc}") from exc
        digest = hashlib.sha256(data).hexdigest()
        if (record.get("schema_version") != 1 or record.get("target") != target_name or
                record.get("stdin_sha256") != digest or test.get("kind") != "security" or
                not _valid_signature(record.get("expected_baseline_signature")) or
                not _valid_signature(record.get("expected_candidate_signature"))):
            raise PatchGuardError(f"regression-corpus case failed validation: {path}")
        source_name = _safe_component(test.get("name", "security"))
        test["name"] = f"regression_{source_name}_{digest[:12]}"
        test["kind"] = "security"
        cases.append({"path": str(path), "record": record, "test": test, "input": data})
    return cases


def _valid_signature(signature):
    return (isinstance(signature, list) and len(signature) == REPEAT_COUNT and
            all(item is None or (isinstance(item, list) and len(item) == 2 and
                                 all(value is None or isinstance(value, str) for value in item))
                for item in signature))


def _find_stored_case(corpus_root, target_name, digest):
    """Return an existing corpus file for this input, whatever test discovered it.

    Different seeds and scenarios converge on the same minimized input, and every
    stored case is replayed for every later candidate, so duplicates would grow the
    corpus and the runtime without adding coverage.
    """
    target_root = Path(corpus_root) / _safe_component(target_name)
    if not target_root.is_dir():
        return None
    for candidate in sorted(target_root.rglob("*.json")):
        try:
            record = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if record.get("stdin_sha256") == digest:
            return candidate
    return None


def _save_regression_case(corpus_root, target_name, test, input_data, classification,
                          scenario_name, candidate_revision, baseline_runs, candidate_runs):
    digest = hashlib.sha256(input_data).hexdigest()
    existing = _find_stored_case(corpus_root, target_name, digest)
    if existing is not None:
        return {"path": str(existing), "sha256": digest, "created": False}
    folder = Path(corpus_root) / _safe_component(target_name) / _safe_component(test["name"])
    path = folder / f"{digest}.json"
    folder.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": 1,
        "target": target_name,
        "test_definition": test,
        "stdin_sha256": digest,
        "stdin_base64": base64.b64encode(input_data).decode("ascii"),
        "finding_classification": classification,
        "source_scenario": scenario_name,
        "source_candidate_revision": candidate_revision,
        "expected_baseline_signature": _failure_signature(baseline_runs),
        "expected_candidate_signature": _failure_signature(candidate_runs),
    }
    created = not path.exists()
    if created:
        temporary = path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary.replace(path)
    return {"path": str(path), "sha256": digest, "created": created}


def _matches_expected(run, test):
    if run.get("failure") is not None:
        return False
    if run.get("returncode") != int(test.get("expected_exit", 0)):
        return False
    expected = test.get("expected_stdout")
    if expected is not None and run.get("stdout") != expected:
        return False
    contains = test.get("expected_stdout_contains")
    if contains is not None and contains not in run.get("stdout", ""):
        return False
    return True


def _crash_site_for_run(run, source):
    if not run.get("failure"):
        return None
    source_root = Path(source).resolve()
    locations = correlate({"hunks": []}, run.get("stdout", ""), run.get("stderr", ""))["locations"]
    for location in locations:
        try:
            relative_path = Path(str(location["path"]).replace("\\", "/")).resolve().relative_to(source_root)
        except (OSError, ValueError):
            continue
        return {"file": relative_path.as_posix(), "line": location["line"],
                "function": location.get("function")}
    return None


def _crash_site(runs, source=None):
    """Return a crash site; minimization supplies source to require a target frame."""
    if source is None:
        # Fuzz classification also compares baseline and candidate stacks before
        # choosing whether a finding is pre-existing. Preserve its historical
        # location comparison when no source snapshot is available.
        run = next((run for run in runs if run.get("failure")), None)
        if run is None:
            return None
        locations = correlate({"hunks": []}, run.get("stdout", ""), run.get("stderr", ""))["locations"]
        if not locations:
            return None
        first = locations[0]
        return {"file": str(first["path"]).replace("\\", "/").rsplit("/", 1)[-1],
                "line": first["line"], "function": first.get("function")}

    # With a source, return a stable source-local site, skipping library frames.
    sites = [_crash_site_for_run(run, source) for run in runs if run.get("failure")]
    if not sites or any(site is None for site in sites):
        return None
    identities = {_crash_site_identity(site) for site in sites}
    return sites[0] if len(identities) == 1 else None


def _crash_site_identity(site):
    # A function is a more stable identity than a line number when line tables
    # differ; without a function name, require the exact source line as well.
    function = site.get("function")
    return (site.get("file"), function) if function else (site.get("file"), site.get("line"))


def _failure_matches_site(run, expected_kind, expected_type, expected_site, source):
    failure = run.get("failure") or {}
    if failure.get("kind") != expected_kind:
        return False
    if expected_type is not None and failure.get("error_type") != expected_type:
        return False
    observed_site = _crash_site_for_run(run, source)
    return (expected_site is not None and observed_site is not None and
            _crash_site_identity(observed_site) == _crash_site_identity(expected_site))


def _correlation_state(diff, runs, side="old"):
    failures = [run for run in runs if run.get("failure")]
    if not failures:
        return {"related": False, "locations": [], "matches": []}
    evidence = correlate(diff, failures[0].get("stdout", ""), failures[0].get("stderr", ""), side=side)
    evidence["failure_kind"] = failures[0]["failure"]["kind"]
    evidence["error_type"] = failures[0]["failure"].get("error_type")
    return evidence


def _evaluate_test(test, data, baseline_bins, candidate_bins, target, diff, regression_case=None):
    repetitions = REPEAT_COUNT if test["kind"] == "security" else 1
    runs = {"baseline": {}, "candidate": {}}
    for version, binaries in (("baseline", baseline_bins), ("candidate", candidate_bins)):
        for mode, executable in binaries.items():
            runs[version][mode] = _run_many(executable, test, data, target, repetitions)

    if test["kind"] == "functional":
        baseline_ok = all(_matches_expected(run, test)
                          for mode_runs in runs["baseline"].values() for run in mode_runs)
        candidate_runs = [run for mode_runs in runs["candidate"].values() for run in mode_runs]
        candidate_failure = next((run["failure"] for run in candidate_runs if run.get("failure")), None)
        candidate_correlation = _correlation_state(diff, candidate_runs, side="new")
        baseline_launch_error = any((run.get("failure") or {}).get("kind") == "launch_error"
                                    for mode_runs in runs["baseline"].values() for run in mode_runs)
        candidate_ok = all(_matches_expected(run, test) for run in candidate_runs)
        if baseline_launch_error:
            status, code, reason = "BUILD_OR_CONFIG_ERROR", 30, "baseline executable could not be launched"
        elif not baseline_ok:
            status, code, reason = "INCONCLUSIVE", 40, "baseline did not satisfy the documented behavior oracle"
        elif candidate_failure and candidate_failure["kind"] == "launch_error":
            status, code, reason = "BUILD_OR_CONFIG_ERROR", 30, "candidate executable could not be launched"
        elif candidate_failure and candidate_failure["kind"] in {
            "address_sanitizer", "undefined_behavior_sanitizer", "memory_sanitizer",
            "stack_protector", "signal",
        }:
            if candidate_correlation["related"]:
                status, code, reason = "NEW_ISSUE", 10, f"candidate hit {candidate_failure['kind']} on a valid-input test"
            else:
                status, code, reason = "INCONCLUSIVE", 40, "candidate failure could not be linked to a changed code hunk"
        elif not candidate_ok:
            status, code, reason = "FUNCTIONAL_REGRESSION", 20, "candidate changed the expected valid-input behavior"
        else:
            status, code, reason = "PASS", 0, "baseline and candidate satisfy the behavior oracle"
        return {"name": test["name"], "kind": "functional", "status": status, "code": code,
                "reason": reason, "candidate_correlation": candidate_correlation,
                "change_hunks": diff.get("hunks", []), "runs": runs}

    baseline_state = _failure_state(runs["baseline"]["instrumented"])
    candidate_state = _failure_state(runs["candidate"]["instrumented"])
    correlation = _correlation_state(diff, runs["baseline"]["instrumented"], side="old")
    candidate_correlation = _correlation_state(diff, runs["candidate"]["instrumented"], side="new")
    if any((run.get("failure") or {}).get("kind") == "launch_error"
           for version_runs in runs.values() for mode_runs in version_runs.values() for run in mode_runs):
        status, code, reason = "BUILD_OR_CONFIG_ERROR", 30, "one of the target binaries could not be launched"
    elif regression_case is not None:
        record = regression_case["record"]
        baseline_signature = _failure_signature(runs["baseline"]["instrumented"])
        if baseline_signature != record["expected_baseline_signature"]:
            status, code, reason = "INCONCLUSIVE", 40, "regression-corpus baseline behavior changed since the case was recorded"
        elif not any(run.get("failure") for run in runs["candidate"]["instrumented"]):
            status, code, reason = "FIXED", 0, "candidate passes the previously discovered regression-corpus input"
        elif not candidate_state["stable"]:
            status, code, reason = "INCONCLUSIVE", 40, "candidate regression-corpus failure was not stable across three repetitions"
        elif (baseline_state["stable"] and
              (candidate_state["kind"], candidate_state["error_type"]) ==
              (baseline_state["kind"], baseline_state["error_type"])):
            status, code, reason = "VULN_REMAINS", 10, f"candidate still triggers {candidate_state['kind']} on a stored regression input"
        elif candidate_correlation["related"]:
            status, code, reason = "NEW_ISSUE", 10, f"candidate triggers {candidate_state['kind']} on a stored regression input"
        else:
            status, code, reason = "INCONCLUSIVE", 40, "stored regression-corpus failure could not be linked to a changed code hunk"
    elif not baseline_state["stable"]:
        status, code, reason = "INCONCLUSIVE", 40, "the vulnerable baseline did not reproduce one stable instrumented failure three times"
    elif not correlation["related"]:
        status, code, reason = "INCONCLUSIVE", 40, "the baseline finding could not be linked to a changed code hunk"
    elif not candidate_state["stable"] and any(run.get("failure") for run in runs["candidate"]["instrumented"]):
        status, code, reason = "INCONCLUSIVE", 40, "candidate failure was not stable across three repetitions"
    elif candidate_state["stable"]:
        if (candidate_state["kind"], candidate_state["error_type"]) == (baseline_state["kind"], baseline_state["error_type"]):
            status, code, reason = "VULN_REMAINS", 10, f"candidate still triggers {candidate_state['kind']}"
        elif candidate_correlation["related"]:
            status, code, reason = "NEW_ISSUE", 10, f"candidate triggers a different failure: {candidate_state['kind']}/{candidate_state['error_type']}"
        else:
            status, code, reason = "INCONCLUSIVE", 40, "candidate failure could not be linked to a changed code hunk"
    else:
        status, code, reason = "FIXED", 0, "baseline finding is reproducible and candidate does not trigger it"
    result = {"name": test["name"], "kind": "security", "status": status, "code": code,
              "reason": reason, "correlation": correlation,
              "candidate_correlation": candidate_correlation, "runs": runs}
    if regression_case is not None:
        record = regression_case["record"]
        result["regression_corpus"] = {
            "path": regression_case["path"],
            "sha256": record["stdin_sha256"],
            "source_scenario": record.get("source_scenario"),
            "source_candidate_revision": record.get("source_candidate_revision"),
            "previous_candidate_signature": record["expected_candidate_signature"],
        }
    return result


def _write_reproducer(bundle_root, test, input_data, target, source, finding, executable,
                      baseline=False, revision=None, reference_runs=None):
    bundle_root.mkdir(parents=True, exist_ok=True)
    minimized = input_data
    attempts = 0
    replay = []
    replay_state = None
    original_crash_site = None
    minimized_crash_site = None
    crash_site_preserved = None
    binary = _binary_record(executable)
    if finding and test["kind"] == "security":
        expected_kind = finding["kind"] if isinstance(finding, dict) else finding
        expected_type = finding.get("error_type") if isinstance(finding, dict) else None
        reference_runs = reference_runs or _run_many(executable, test, input_data, target, REPEAT_COUNT)
        original_crash_site = _crash_site(reference_runs, source)
        if original_crash_site is not None:
            def reproduces(candidate):
                result = run_program(executable, test, candidate, float(target.get("timeout_seconds", 3)),
                                     target.get("environment"), target.get("limits"))
                return _failure_matches_site(
                    result, expected_kind, expected_type, original_crash_site, source
                )

            site_key = _crash_site_identity(original_crash_site)
            cache_key = (binary.get("sha256"), hashlib.sha256(input_data).hexdigest(),
                         expected_kind, expected_type, site_key)
            cached = _MINIMIZATION_CACHE.get(cache_key) if binary.get("available") else None
            if cached is None:
                minimized, attempts = minimize_bytes(input_data, reproduces)
                if binary.get("available"):
                    _MINIMIZATION_CACHE[cache_key] = (minimized, attempts)
            else:
                minimized, attempts = cached
            replay = _run_many(executable, test, minimized, target, REPEAT_COUNT)
            replay_state = _failure_state(replay)
            minimized_crash_site = _crash_site(replay, source)
            if (not replay_state["stable"] or replay_state["kind"] != expected_kind or
                    (expected_type is not None and replay_state["error_type"] != expected_type) or
                    minimized_crash_site is None or
                    _crash_site_identity(minimized_crash_site) != site_key):
                minimized = input_data
                replay = reference_runs
                replay_state = _failure_state(replay)
                minimized_crash_site = original_crash_site
            crash_site_preserved = (
                minimized_crash_site is not None and
                _crash_site_identity(minimized_crash_site) == site_key
            )
        else:
            # Without a source-local site, the tool cannot prove that a smaller
            # input preserves this particular finding. Keep the original input.
            replay = reference_runs
            replay_state = _failure_state(replay)
            minimized_crash_site = original_crash_site
            crash_site_preserved = False
    elif finding:
        replay = _run_many(executable, test, input_data, target, 1)

    payload = {
        "test": test["name"],
        "kind": test["kind"],
        "test_definition": test,
        "source_role": "vulnerable_baseline" if baseline else "candidate",
        "source_fingerprint": source_fingerprint(source),
        "git_commit": revision or git_revision(source),
        "timeout_seconds": target.get("timeout_seconds", 3),
        "resource_limits": {
            "output_bytes": int(target.get("limits", {}).get("output_bytes", 2 * 1024 * 1024)),
            "cpu_seconds_soft": max(1, int(float(target.get("timeout_seconds", 3))) + 1),
            "core_dumps": False,
            "open_files": 64,
            "wall_seconds": float(target.get("timeout_seconds", 3)),
        },
        "argv": test.get("argv", []),
        "command": [str(executable)] + [str(value) for value in test.get("argv", [])],
        "build_commands": target.get("_build_commands", target["build"]),
        "compiler_versions": target.get("_compiler_versions", {}),
        "build_environment": target.get("_build_environment", target.get("build_environment", {})),
        "runtime_environment": target.get("_runtime_environment", {
            "LANG": "C",
            "LC_ALL": "C",
            "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=0",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            **{str(k): str(v) for k, v in target.get("environment", {}).items()},
        }),
        "host_environment": {
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": sys.version,
        },
        "finding": finding,
        "binary": binary,
        "replay_stable": None if replay_state is None else replay_state["stable"],
        "reproduction_count": REPEAT_COUNT if test["kind"] == "security" else 1,
        "minimization_attempts": attempts,
        "original_crash_site": original_crash_site,
        "minimized_crash_site": minimized_crash_site,
        "crash_site_preserved": crash_site_preserved,
        "original_stdin_sha256": hashlib.sha256(input_data).hexdigest(),
        "minimized_stdin_sha256": hashlib.sha256(minimized).hexdigest(),
        "original_stdin_base64": base64.b64encode(input_data).decode("ascii"),
        "minimized_stdin_base64": base64.b64encode(minimized).decode("ascii"),
        "minimized_replay_runs": replay,
    }
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", test["name"])
    (bundle_root / f"{safe_name}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _binary_record(executable):
    path = Path(executable)
    try:
        stat = path.stat()
        digest = file_sha256(path)
    except OSError as exc:
        return {"path": str(path), "available": False, "reason": str(exc)}
    return {"path": str(path), "available": True, "sha256": digest, "size": stat.st_size}


def _classify_fuzz_finding(baseline_runs, candidate_runs, diff):
    baseline_state = _failure_state(baseline_runs)
    candidate_state = _failure_state(candidate_runs)
    if not candidate_state["stable"]:
        return "INCONCLUSIVE", _correlation_state(diff, candidate_runs, side="new"), baseline_state

    baseline_has_failures = any(run.get("failure") for run in baseline_runs)
    if baseline_has_failures and not baseline_state["stable"]:
        return "INCONCLUSIVE", _correlation_state(diff, baseline_runs, side="old"), baseline_state

    if baseline_state["stable"] and (baseline_state["kind"], baseline_state["error_type"]) == (
        candidate_state["kind"], candidate_state["error_type"]
    ):
        correlation = _correlation_state(diff, baseline_runs, side="old")
        if _crash_site(baseline_runs) is not None and _crash_site(baseline_runs) == _crash_site(candidate_runs):
            return "VULN_REMAINS", correlation, baseline_state
        if correlation["related"]:
            return "VULN_REMAINS", correlation, baseline_state
        # The same failure class exists in both builds at a different site and has
        # no link to the patch: a pre-existing defect of the target, not this patch.
        return "PRE_EXISTING_UNRELATED", correlation, baseline_state
    correlation = _correlation_state(diff, candidate_runs, side="new")
    classification = "NEW_ISSUE" if correlation["related"] else "INCONCLUSIVE"
    return classification, correlation, baseline_state


def _fuzz_candidate(target, baseline_bins, candidate_bins, workspace, scenario_root, diff, seed, iterations,
                    corpus_root, scenario_name):
    if iterations <= 0:
        return []
    rng = random.Random(seed)
    fuzz_tests = [test for test in target["tests"] if test.get("fuzz", False)]
    findings = []
    candidate_source = target.get("_candidate_source")
    candidate_revision = target.get("_candidate_revision")
    for test in fuzz_tests:
        original = test_input(test, workspace)
        for iteration in range(iterations):
            mutated = mutate(original, rng)
            candidate_runs = _run_many(candidate_bins["instrumented"], test, mutated, target, REPEAT_COUNT)
            candidate_state = _failure_state(candidate_runs)
            if not any(run.get("failure") for run in candidate_runs):
                continue
            if not candidate_state["stable"]:
                findings.append({
                    "test": test["name"],
                    "classification": "INCONCLUSIVE",
                    "reason": "fuzz candidate failure was not stable across three repetitions",
                    "input_base64": base64.b64encode(mutated).decode("ascii"),
                    "runs": candidate_runs,
                    "iteration": iteration,
                })
                continue
            baseline_runs = _run_many(baseline_bins["instrumented"], test, mutated, target, REPEAT_COUNT)
            classification, correlation, _ = _classify_fuzz_finding(
                baseline_runs, candidate_runs, diff
            )
            finding = _write_reproducer(
                scenario_root / "fuzz_reproducers", test, mutated, target, candidate_source,
                candidate_state, candidate_bins["instrumented"], baseline=False, revision=candidate_revision,
                reference_runs=candidate_runs,
            )
            minimized = base64.b64decode(finding["minimized_stdin_base64"], validate=True)
            minimized_candidate_runs = finding["minimized_replay_runs"]
            minimized_baseline_runs = _run_many(
                baseline_bins["instrumented"], test, minimized, target, REPEAT_COUNT
            )
            classification, correlation, minimized_baseline_state = _classify_fuzz_finding(
                minimized_baseline_runs, minimized_candidate_runs, diff
            )
            finding["classification"] = classification
            finding["correlation"] = correlation
            finding["baseline_state"] = minimized_baseline_state
            finding["baseline_runs"] = minimized_baseline_runs
            finding["candidate_runs"] = minimized_candidate_runs
            finding["original_baseline_runs"] = baseline_runs
            finding["original_candidate_runs"] = candidate_runs
            finding["iteration"] = iteration
            if classification in {"VULN_REMAINS", "NEW_ISSUE"}:
                finding["regression_corpus_case"] = _save_regression_case(
                    corpus_root, target["name"], test,
                    minimized, classification, scenario_name, candidate_revision,
                    minimized_baseline_runs, minimized_candidate_runs,
                )
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", test["name"])
            (scenario_root / "fuzz_reproducers" / f"{safe_name}.json").write_text(
                json.dumps(finding, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            findings.append(finding)
            if classification != "INCONCLUSIVE":
                break
    return findings


def _evaluate_scenario(target, scenario, workspace, output_root, fuzz_seed):
    name = target["name"]
    baseline_ref = target["versions"]["vulnerable"]
    candidate_name = scenario.get("candidate")
    before_revision = None
    candidate_revision = None
    repository = target.get("_repository")
    scenario_root = Path(output_root) / name / scenario["name"]
    scenario_root.mkdir(parents=True, exist_ok=True)
    if repository:
        repository = prepare_repository(repository, scenario_root)
        before_revision = ref_revision(repository, baseline_ref)
        if not before_revision:
            raise PatchGuardError(f"{name}: could not resolve baseline Git ref {baseline_ref!r}")
        before = extract_ref(repository, baseline_ref, before_revision, scenario_root, "baseline")
    else:
        before = Path(baseline_ref)

    if scenario.get("_candidate_path"):
        after = Path(scenario["_candidate_path"]).resolve()
        candidate_name = "unseen-patch"
        if repository:
            candidate_revision = git_revision(after)
        diff = directory_diff(before, after)
    elif repository:
        candidate_ref = target["versions"][candidate_name]
        candidate_revision = ref_revision(repository, candidate_ref)
        if not candidate_revision:
            raise PatchGuardError(f"{name}: could not resolve candidate Git ref {candidate_ref!r}")
        after = extract_ref(repository, candidate_ref, candidate_revision, scenario_root, "candidate")
        diff = revision_diff(repository, baseline_ref, candidate_ref)
    else:
        after = Path(target["versions"][candidate_name])
        diff = directory_diff(before, after)
    if not after.is_dir():
        raise PatchGuardError(f"{name}/{scenario['name']}: candidate source directory does not exist: {after}")

    if diff["error"]:
        return {"name": scenario["name"], "candidate": candidate_name, "status": "BUILD_OR_CONFIG_ERROR",
                "code": 30, "error": diff["error"], "diff": diff["text"]}

    build_results = {"baseline": {}, "candidate": {}}
    for role, source in (("baseline", before), ("candidate", after)):
        for mode in ("release", "instrumented"):
            try:
                build_results[role][mode] = build_target(
                    target, source, workspace, scenario_root / "build" / role / mode, mode
                )
            except BuildError as exc:
                if exc.record:
                    build_results[role][mode] = exc.record
                return {"name": scenario["name"], "candidate": candidate_name,
                        "status": "BUILD_OR_CONFIG_ERROR", "code": 30,
                        "error": str(exc), "builds": build_results, "diff": diff["text"]}

    baseline_bins = {mode: record["executable"] for mode, record in build_results["baseline"].items()}
    candidate_bins = {mode: record["executable"] for mode, record in build_results["candidate"].items()}
    target_for_evidence = dict(target)
    target_for_evidence["_build_commands"] = {
        role: {mode: record["command"] for mode, record in modes.items()}
        for role, modes in build_results.items()
    }
    target_for_evidence["_build_environment"] = {
        role: {mode: record.get("environment", {}) for mode, record in modes.items()}
        for role, modes in build_results.items()
    }
    target_for_evidence["_compiler_versions"] = {
        role: {mode: record.get("compiler_version") for mode, record in modes.items()}
        for role, modes in build_results.items()
    }
    corpus_root = Path(target["_regression_corpus"])
    regression_cases = _load_regression_cases(corpus_root, name)
    test_entries = [(test, test_input(test, workspace), None) for test in target["tests"]]
    ordinary_hashes = {(test["kind"], hashlib.sha256(data).hexdigest())
                       for test, data, _ in test_entries}
    replayed_cases = []
    for case in regression_cases:
        key = (case["test"]["kind"], hashlib.sha256(case["input"]).hexdigest())
        if key in ordinary_hashes:
            continue
        test_entries.append((case["test"], case["input"], case))
        replayed_cases.append(case)

    test_results = []
    for test, input_data, regression_case in test_entries:
        result = _evaluate_test(test, input_data, baseline_bins, candidate_bins, target_for_evidence,
                                diff, regression_case=regression_case)
        test_results.append(result)
        first_run = result["runs"]["candidate"].get("instrumented", result["runs"]["candidate"]["release"])[0]
        target_for_evidence["_runtime_environment"] = first_run.get("environment", {})
        if test["kind"] == "security":
            baseline_finding = _failure_state(result["runs"]["baseline"]["instrumented"])
            if baseline_finding["stable"]:
                _write_reproducer(
                    scenario_root / "reproducers" / "baseline", test, input_data, target_for_evidence, before,
                    baseline_finding, baseline_bins["instrumented"], baseline=True,
                    revision=before_revision,
                    reference_runs=result["runs"]["baseline"]["instrumented"],
                )
            candidate_finding = _failure_state(result["runs"]["candidate"]["instrumented"])
            if candidate_finding["stable"]:
                candidate_bundle = _write_reproducer(
                    scenario_root / "reproducers" / "candidate", test, input_data, target_for_evidence, after,
                    candidate_finding, candidate_bins["instrumented"], baseline=False,
                    revision=candidate_revision,
                    reference_runs=result["runs"]["candidate"]["instrumented"],
                )
                # Only configured tests may seed the corpus: replaying a stored case
                # must not store another copy of itself under a derived name.
                if regression_case is None and result["status"] in {"VULN_REMAINS", "NEW_ISSUE"}:
                    minimized_input = base64.b64decode(candidate_bundle["minimized_stdin_base64"], validate=True)
                    result["regression_corpus_case"] = _save_regression_case(
                        corpus_root, name, test, minimized_input, result["status"], scenario["name"],
                        candidate_revision, result["runs"]["baseline"]["instrumented"],
                        result["runs"]["candidate"]["instrumented"],
                    )
        elif result["code"] != 0:
            _write_reproducer(
                scenario_root / "reproducers" / "candidate", test, input_data, target_for_evidence, after,
                result["status"], candidate_bins["release"], baseline=False, revision=candidate_revision,
            )

    hardening = {
        "baseline": inspect_elf(baseline_bins["release"]),
        "candidate": inspect_elf(candidate_bins["release"]),
    }
    hardening["comparison"] = compare_hardening(hardening["baseline"], hardening["candidate"])
    target_for_fuzz = dict(target_for_evidence)
    target_for_fuzz["_candidate_name"] = candidate_name
    target_for_fuzz["_candidate_source"] = str(after)
    target_for_fuzz["_candidate_revision"] = candidate_revision
    if scenario.get("_candidate_path"):
        target_for_fuzz["_candidate_path"] = str(after)
    scenario_fuzz_seed = fuzz_seed + sum(ord(char) for char in f"{name}/{scenario['name']}")
    fuzz_findings = _fuzz_candidate(
        target_for_fuzz, baseline_bins, candidate_bins, workspace, scenario_root, diff,
        seed=scenario_fuzz_seed,
        iterations=int(target.get("fuzz_iterations", 0)),
        corpus_root=corpus_root,
        scenario_name=scenario["name"],
    )
    codes = [item["code"] for item in test_results]
    # Only attributed fuzz findings can change the verdict. Unstable repeats and
    # pre-existing crashes outside the patch stay recorded in the report without
    # turning a conclusive scenario into INCONCLUSIVE.
    codes.extend(10 for item in fuzz_findings
                 if item["classification"] in {"VULN_REMAINS", "NEW_ISSUE"})
    code = _aggregate(codes)
    test_statuses = {item["status"] for item in test_results}
    fuzz_statuses = {item["classification"] for item in fuzz_findings}
    if code == 10 and "NEW_ISSUE" in (test_statuses | fuzz_statuses):
        status = "NEW_ISSUE"
    elif code == 10 and "VULN_REMAINS" in (test_statuses | fuzz_statuses):
        fixed_security_test = any(item["kind"] == "security" and item["status"] == "FIXED"
                                  for item in test_results)
        status = "INCOMPLETE_FIX" if fixed_security_test else "VULN_REMAINS"
    else:
        status = {
            0: "PASS",
            10: "SECURITY_FINDING",
            20: "FUNCTIONAL_REGRESSION",
            30: "BUILD_OR_CONFIG_ERROR",
            40: "INCONCLUSIVE",
        }[code]
    return {
        "name": scenario["name"],
        "candidate": candidate_name,
        "status": status,
        "code": code,
        "source": {
            "baseline": {"path": str(before), "fingerprint": source_fingerprint(before),
                         "git_commit": before_revision or git_revision(before)},
            "candidate": {"path": str(after), "fingerprint": source_fingerprint(after),
                          "git_commit": candidate_revision or git_revision(after)},
        },
        "builds": build_results,
        "diff": {"text": diff["text"], "hunks": diff["hunks"]},
        "tests": test_results,
        "regression_corpus": {
            "root": str(corpus_root),
            "loaded_cases": len(regression_cases),
            "replayed_cases": [
                {"path": case["path"], "sha256": case["record"]["stdin_sha256"],
                 "test": case["test"]["name"]}
                for case in replayed_cases
            ],
            "new_cases": [item["regression_corpus_case"] for item in
                          list(fuzz_findings) + list(test_results)
                          if item.get("regression_corpus_case", {}).get("created")],
        },
        "hardening": hardening,
        "fuzz": {"seed": scenario_fuzz_seed,
                 "iterations_per_seed": int(target.get("fuzz_iterations", 0)),
                 "findings": fuzz_findings},
    }


def evaluate_project(project, output_root, target_filter=None, scenario_filter=None, candidate_overrides=None):
    workspace = Path(project["_workspace"])
    candidate_overrides = candidate_overrides or {}
    targets = []
    all_codes = []
    for target in project["targets"]:
        if target_filter and target["name"] not in target_filter:
            continue
        scenarios = list(target["scenarios"])
        if target["name"] in candidate_overrides:
            scenarios.append({"name": "unseen-patch", "candidate": "unseen-patch",
                              "_candidate_path": candidate_overrides[target["name"]]})
        if scenario_filter:
            scenarios = [scenario for scenario in scenarios if scenario["name"] in scenario_filter]
            if not scenarios:
                continue
        scenario_results = []
        for scenario in scenarios:
            try:
                scenario_result = _evaluate_scenario(
                    {**target, "_regression_corpus": project["_regression_corpus"]},
                    scenario, workspace, output_root,
                    int(project.get("fuzz_seed", 2026)),
                )
            except (PatchGuardError, OSError, ValueError, TypeError) as exc:
                scenario_result = {"name": scenario.get("name", "unknown"),
                                   "status": "BUILD_OR_CONFIG_ERROR", "code": 30, "error": str(exc)}
            scenario_results.append(scenario_result)
            all_codes.append(scenario_result["code"])
        targets.append({"name": target["name"], "scenarios": scenario_results})

    if not targets or not any(target["scenarios"] for target in targets):
        raise PatchGuardError("the selected target/scenario combination did not match any configured scenario")
    code = _aggregate(all_codes)
    return {
        "tool": "PatchGuard",
        "schema_version": 1,
        "status": {0: "PASS", 10: "SECURITY_FINDING", 20: "FUNCTIONAL_REGRESSION",
                   30: "BUILD_OR_CONFIG_ERROR", 40: "INCONCLUSIVE"}[code],
        "exit_code": code,
        "targets": targets,
    }
