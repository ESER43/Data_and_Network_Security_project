import json
from pathlib import Path
import subprocess

from .errors import PatchGuardError


def _need(condition, message):
    if not condition:
        raise PatchGuardError(message)


def load_project(path):
    config_path = Path(path).resolve()
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PatchGuardError(f"cannot read project config {config_path}: {exc}") from exc

    _need(data.get("schema_version") == 1, "schema_version must be 1")
    _need(isinstance(data.get("targets"), list) and data["targets"], "targets must be a non-empty list")
    workspace = Path(data.get("workspace", "."))
    if not workspace.is_absolute():
        workspace = (config_path.parent / workspace).resolve()
    data["_config_path"] = str(config_path)
    data["_workspace"] = str(workspace)
    regression_corpus = Path(data.get("regression_corpus", "regression_corpus"))
    if not regression_corpus.is_absolute():
        regression_corpus = (workspace / regression_corpus).resolve()
    data["_regression_corpus"] = str(regression_corpus)

    seen = set()
    for target in data["targets"]:
        _need(isinstance(target, dict), "each target must be an object")
        name = target.get("name")
        _need(isinstance(name, str) and name, "each target needs a name")
        _need(name not in seen, f"duplicate target name: {name}")
        seen.add(name)
        repository = target.get("repository")
        if repository:
            repository_path = Path(repository)
            if not repository_path.is_absolute():
                repository_path = (workspace / repository_path).resolve()
            _need(repository_path.exists(), f"{name}: repository or bundle does not exist: {repository_path}")
            target["_repository"] = str(repository_path)
        versions = target.get("versions", {})
        _need(isinstance(versions, dict), f"{name}: versions must be an object")
        _need("vulnerable" in versions, f"{name}: versions must include vulnerable")
        scenarios = target.get("scenarios", [])
        _need(isinstance(scenarios, list) and scenarios, f"{name}: scenarios must be a non-empty list")
        _need(isinstance(target.get("tests"), list) and target["tests"], f"{name}: tests must be a non-empty list")
        build = target.get("build", {})
        _need(isinstance(build, dict), f"{name}: build must be an object")
        _need(isinstance(build.get("release"), list), f"{name}: build.release must be an argv list")
        _need(isinstance(build.get("instrumented"), list), f"{name}: build.instrumented must be an argv list")
        _need(isinstance(build.get("executable"), str), f"{name}: build.executable is required")
        _need(float(target.get("timeout_seconds", 3)) > 0, f"{name}: timeout_seconds must be positive")

        for version_name, source in versions.items():
            if repository:
                if repository_path.is_file():
                    result = subprocess.run(
                        ["git", "bundle", "list-heads", str(repository_path)],
                        capture_output=True, text=True, check=False,
                    )
                    available_refs = {line.split()[-1].removeprefix("refs/heads/")
                                      for line in result.stdout.splitlines() if len(line.split()) == 2}
                    _need(result.returncode == 0 and source in available_refs,
                          f"{name}: bundle ref {source!r} for {version_name!r} does not exist")
                else:
                    result = subprocess.run(
                        ["git", "-C", str(repository_path), "rev-parse", "--verify", f"{source}^{{commit}}"],
                        capture_output=True, text=True, check=False,
                    )
                    _need(result.returncode == 0, f"{name}: Git ref {source!r} for {version_name!r} does not resolve")
            else:
                source_path = Path(source)
                if not source_path.is_absolute():
                    source_path = (workspace / source_path).resolve()
                _need(source_path.is_dir(), f"{name}: source directory for {version_name!r} does not exist: {source_path}")
                versions[version_name] = str(source_path)

        scenario_names = set()
        for scenario in scenarios:
            _need(isinstance(scenario, dict), f"{name}: scenario must be an object")
            scenario_name = scenario.get("name")
            candidate = scenario.get("candidate")
            _need(isinstance(scenario_name, str) and scenario_name, f"{name}: scenario needs a name")
            _need(scenario_name not in scenario_names, f"{name}: duplicate scenario {scenario_name}")
            scenario_names.add(scenario_name)
            _need(candidate in versions, f"{name}/{scenario_name}: unknown candidate version {candidate!r}")

        for test in target["tests"]:
            _need(isinstance(test, dict), f"{name}: each test must be an object")
            _need(test.get("kind") in {"security", "functional"}, f"{name}: test kind must be security or functional")
            _need(isinstance(test.get("name"), str), f"{name}: every test needs a name")
            _need("stdin" in test or "stdin_base64" in test or "stdin_file" in test,
                  f"{name}/{test.get('name')}: provide stdin, stdin_base64, or stdin_file")

    return data


def test_input(test, workspace):
    import base64

    if "stdin_base64" in test:
        return base64.b64decode(test["stdin_base64"], validate=True)
    if "stdin_file" in test:
        input_path = Path(test["stdin_file"])
        if not input_path.is_absolute():
            input_path = Path(workspace) / input_path
        return input_path.read_bytes()
    return test.get("stdin", "").encode("utf-8")
