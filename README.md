# PatchGuard

PatchGuard is a small, configurable evaluator for security patches in native C/C++ programs on Linux x86-64. It compares Git revisions, builds release and sanitizer-instrumented binaries, runs documented valid and security-focused inputs, links sanitizer locations to changed hunks, and writes a JSON report.

The implementation uses only the Python standard library (Python 3.9 or newer). The target programs and compiler must be available in a Linux x86-64 environment with cc, git, and readelf.

## Run

From this directory on Linux:

    python3 -m patchguard project.json

The report is written to artifacts/latest.json; per-scenario build logs and reproduction bundles are placed under artifacts/latest/. Run a single scenario with:

    python3 -m patchguard project.json --scenario correct-patch

For a function-by-function explanation and execution flowchart, see [CODE_WALKTHROUGH.md](CODE_WALKTHROUGH.md).

Evaluate an unseen patch by pointing the tool at a source directory containing its main.c:

    python3 -m patchguard project.json --target inih-config-bridge \
      --scenario unseen-patch \
      --candidate inih-config-bridge=path/to/unseen/source \
      --output artifacts/unseen.json

The unfiltered demo intentionally evaluates incomplete and regression examples, so its project-level result is expected to be code 10: security findings outrank functional regressions per the assignment. The CI workflow runs each expected status separately.

Each test is run on baseline and candidate release and instrumented builds. Security findings are repeated three times. Each target runs in its own process group with wall-clock and CPU limits, bounded output/file size and open descriptors, and core dumps disabled. A deterministic mutator runs 32 additional inputs for each fuzz-enabled test and scenario (configurable as `fuzz_iterations`). Confirmed fuzz findings are minimized, stored as regression-corpus cases, and replayed against later candidates. Diff-correlation evidence records direct changed-line matches and nearby matches only when stack trace and Git hunk identify the same function; file paths are matched by their full path suffix rather than filename alone. Reproducer records include the original and minimized input, replay observations, source fingerprint, Git commit when available, host/compiler environment, and build/run details.

The checked-in `regression_corpus/` contains a minimized overflow already confirmed on the incomplete capacity-reader patch. New confirmed fuzz findings are added there automatically. CI restores and updates this corpus between workflow runs and uploads it with the JSON reports.

## Included targets

* **cjson** is based on the real upstream [cJSON](https://github.com/DaveGamble/cJSON) C library. Its vulnerable baseline is the upstream `v1.7.17` commit, where `cJSON_SetValuestring` can dereference a NULL replacement string; the correct benchmark branch applies the upstream fix commit `7e4d5da`. The checked-in driver only turns stdin into calls to this library function; the defect and fix are in upstream `cJSON.c`. The upstream MIT license is retained.
* **inih-config-bridge** builds and runs the upstream [inih](https://github.com/benhoyt/inih) C INI parser. Its vulnerable behavior is in a small downstream application callback that stores parsed configuration values; it demonstrates unsafe use of a real parser library, not a vulnerability claim against upstream inih. The upstream source is vendored in vendor/inih and its BSD license is retained.
* **capacity-reader** demonstrates an integer-wrap allocation bug in a command-line input reader. Correct variants reject capacities above 4096 so untrusted input cannot request unbounded memory.

All three benchmark Git bundles contain vulnerable, correct, incomplete, regression, and unseen branches. The cJSON vulnerable and correct branches are based on the upstream code and security fix; the incomplete, regression, and unseen branches are controlled benchmark variants. Across the targets, incomplete variants stop the supplied first reproducer but retain a related flaw, regression variants reject a valid boundary input, and unseen-style variants use a different safe coding pattern.

The cJSON tests call the actual library API with a NULL replacement pointer and ordinary and boundary strings. This makes the target a real, non-toy open-source C project while keeping the reproducer small enough to explain during the defense.

The fixtures are deliberately small enough to explain during a defense. The evaluator itself is configuration-driven and does not classify results by branch name.

| Scenario | Expected result |
|---|---|
| correct-patch | Code 0 on both targets |
| incomplete-patch | Code 10 because the alternate input still triggers the original flaw |
| regression-patch | Code 20 because a valid boundary input is rejected |
| unseen-style-patch | Code 0 using a different safe implementation pattern |

## Result codes

| Code | Meaning |
|---:|---|
| 0 | Required security findings are fixed and the functional tests pass |
| 10 | A vulnerability remains or a new security failure is observed |
| 20 | A valid-input behavior regression is observed |
| 30 | Build or configuration error |
| 40 | Evidence is inconclusive |

The assignment's exit-code priority is 30, 10, 20, 40, then 0. For the included full suite, code 10 takes priority over the intentional code-20 regression examples. A passing result is returned only when all required checks pass. The JSON report retains every per-test result and finding, even when the summary exit code reflects only the highest-priority status.

## Pipeline

1. Resolve baseline and candidate Git revisions and save their commit hashes.
2. Generate the Git diff and changed-line hunks.
3. Build release and AddressSanitizer/UndefinedBehaviorSanitizer binaries with matching hardening flags.
4. Run the valid-input oracle and the security inputs against both builds.
5. Repeat security findings three times and relate reported source locations to changed hunks.
6. Minimize stable reproducer inputs, save confirmed findings into the regression corpus, replay stored cases, and run deterministic mutations from selected seeds.
7. Compare NX, PIE, RELRO, and stack-canary properties and warn if the candidate weakens any of them.
8. Save findings and reproduction metadata as JSON and return the documented exit code.

## Adding a target

Add a target repository path, Git refs, build argument arrays, tests, and scenarios to project.json. Use the {workspace}, {source}, and {build} placeholders in build arguments. Tests use either stdin, stdin_base64, or stdin_file; functional tests should specify an expected exit code and exact or contained standard output.

Security tests must reproduce a sanitizer error, fatal signal, or timeout on the vulnerable baseline. If the baseline finding is not stable or its source location cannot be associated with a changed hunk, PatchGuard reports INCONCLUSIVE.

## Team contribution guide

* **Pipeline owner:** configuration, compiler invocation, release/instrumented builds, process capture, CI, and exit-code reporting.
* **Patch-analysis owner:** Git diff, location-to-hunk correlation, classification, and ELF hardening comparison.
* **Test/reproduction owner:** test oracles, repeatability, reproduction bundles, minimization, and deterministic mutation corpus.

All members should contribute code and evidence for at least one target scenario, review the shared result schema, and prepare to explain design, analysis, and implementation in the individual defense.
