import argparse
import json
import sys
from pathlib import Path

from .config import load_project
from .errors import PatchGuardError
from .evaluate import evaluate_project
from .process import require_linux_x86_64


def _candidate(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("candidate must be TARGET=SOURCE_DIRECTORY")
    name, path = value.split("=", 1)
    if not name or not path:
        raise argparse.ArgumentTypeError("candidate must be TARGET=SOURCE_DIRECTORY")
    return name, path


def main(argv=None):
    parser = argparse.ArgumentParser(prog="patchguard", description="Evaluate native security patches with reproducible runs.")
    parser.add_argument("config", nargs="?", default="project.json", help="project JSON configuration")
    parser.add_argument("--output", help="JSON report path (default: workspace/artifacts/latest.json)")
    parser.add_argument("--target", action="append", help="limit evaluation to a target; may be repeated")
    parser.add_argument("--scenario", action="append", help="limit evaluation to a scenario; may be repeated")
    parser.add_argument("--candidate", action="append", type=_candidate, default=[],
                        metavar="TARGET=DIR", help="evaluate an unseen candidate source directory")
    args = parser.parse_args(argv)

    try:
        require_linux_x86_64()
        project = load_project(args.config)
        workspace = Path(project["_workspace"])
        target_names = {target["name"] for target in project["targets"]}
        unknown_targets = set(args.target or []) - target_names
        if unknown_targets:
            raise PatchGuardError(f"unknown target(s): {', '.join(sorted(unknown_targets))}")
        unknown_candidate_targets = {name for name, _ in args.candidate} - target_names
        if unknown_candidate_targets:
            raise PatchGuardError(f"unknown candidate target(s): {', '.join(sorted(unknown_candidate_targets))}")
        scenario_names = {scenario["name"] for target in project["targets"] for scenario in target["scenarios"]}
        if args.candidate:
            scenario_names.add("unseen-patch")
        unknown_scenarios = set(args.scenario or []) - scenario_names
        if unknown_scenarios:
            raise PatchGuardError(f"unknown scenario(s): {', '.join(sorted(unknown_scenarios))}")
        candidates = {}
        for name, path in args.candidate:
            candidate_path = Path(path)
            if not candidate_path.is_absolute():
                candidate_path = (workspace / candidate_path).resolve()
            candidates[name] = str(candidate_path)
        output_path = Path(args.output) if args.output else workspace / "artifacts" / "latest.json"
        if not output_path.is_absolute():
            output_path = (workspace / output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = evaluate_project(
            project,
            output_path.parent / output_path.stem,
            target_filter=set(args.target) if args.target else None,
            scenario_filter=set(args.scenario) if args.scenario else None,
            candidate_overrides=candidates,
        )
        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({"status": report["status"], "exit_code": report["exit_code"],
                          "report": str(output_path)}, ensure_ascii=False))
        return report["exit_code"]
    except (PatchGuardError, OSError) as exc:
        print(json.dumps({"status": "BUILD_OR_CONFIG_ERROR", "exit_code": 30, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 30
