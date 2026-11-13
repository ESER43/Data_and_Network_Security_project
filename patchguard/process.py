import os
import platform
import re
import signal
import shutil
import subprocess
import tempfile
from pathlib import Path

from .errors import BuildError, PatchGuardError

_SANITIZER_PATTERNS = (
    ("address_sanitizer", re.compile(r"ERROR: AddressSanitizer", re.IGNORECASE)),
    ("undefined_behavior_sanitizer", re.compile(r"runtime error:", re.IGNORECASE)),
    ("stack_protector", re.compile(r"stack smashing detected|stack-buffer-overflow", re.IGNORECASE)),
    ("memory_sanitizer", re.compile(r"MemorySanitizer", re.IGNORECASE)),
)


def require_linux_x86_64():
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise PatchGuardError("PatchGuard targets Linux x86-64 ELF programs. Run it from Linux or an available WSL distribution.")


def _expand(command, values):
    return [str(part).format_map(values) for part in command]


def build_target(target, source, workspace, build_root, mode):
    build_root = Path(build_root)
    build_root.mkdir(parents=True, exist_ok=True)
    values = {
        "workspace": str(workspace),
        "source": str(source),
        "build": str(build_root),
    }
    command = _expand(target["build"][mode], values)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
    }
    environment.update({str(k): str(v) for k, v in target.get("build_environment", {}).items()})
    try:
        result = subprocess.run(command, cwd=source, capture_output=True, text=True, env=environment, check=False)
    except OSError as exc:
        record = {"command": command, "cwd": str(source), "returncode": None,
                  "stdout": "", "stderr": str(exc), "environment": environment}
        raise BuildError(f"{target['name']} {mode} build could not start: {exc}", record) from exc
    version = subprocess.run([command[0], "--version"], cwd=source, capture_output=True,
                             text=True, env=environment, check=False) if command else None
    record = {
        "command": command,
        "cwd": str(source),
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "environment": environment,
        "compiler_version": (version.stdout or version.stderr).splitlines()[0] if version and (version.stdout or version.stderr) else None,
    }
    if result.returncode != 0:
        raise BuildError(f"{target['name']} {mode} build failed with exit code {result.returncode}", record)
    executable = _expand([target["build"]["executable"]], values)[0]
    if not Path(executable).is_file():
        raise BuildError(f"{target['name']} {mode} build succeeded but executable is missing: {executable}", record)
    record["executable"] = executable
    return record


def run_program(executable, test, input_bytes, timeout_seconds, extra_env=None, limits=None):
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C",
        "LC_ALL": "C",
        "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=0",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }
    if extra_env:
        environment.update({str(k): str(v) for k, v in extra_env.items()})
    argv = [str(executable)] + [str(value) for value in test.get("argv", [])]
    limits = limits or {}
    cpu_seconds = max(1, int(timeout_seconds) + 1)
    output_limit_bytes = int(limits.get("output_bytes", 2 * 1024 * 1024))

    def apply_limits():
        import resource

        _, cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
        if cpu_hard != resource.RLIM_INFINITY:
            cpu_soft_limit = min(cpu_seconds, cpu_hard)
            cpu_hard_limit = min(cpu_soft_limit + 1, cpu_hard)
        else:
            cpu_soft_limit = cpu_seconds
            cpu_hard_limit = cpu_seconds + 1
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_soft_limit, cpu_hard_limit))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _, fsize_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        if fsize_hard != resource.RLIM_INFINITY:
            output_size = min(output_limit_bytes, fsize_hard)
        else:
            output_size = output_limit_bytes
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_size, output_size))
        _, current_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        file_limit = 64 if current_hard == resource.RLIM_INFINITY else min(64, current_hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (file_limit, file_limit))

    limits_record = {
        "cpu_seconds_soft": cpu_seconds,
        "cpu_seconds_hard": cpu_seconds + 1,
        "file_size_bytes": output_limit_bytes,
        "open_files": 64,
        "core_dumps": False,
        "wall_seconds": timeout_seconds,
    }
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=stdout_file,
                stderr=stderr_file,
                env=environment,
                start_new_session=True,
                preexec_fn=apply_limits,
            )
            timed_out = False
            try:
                process.communicate(input=input_bytes, timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            stdout_file.seek(0, os.SEEK_END)
            stdout_size = stdout_file.tell()
            stderr_file.seek(0, os.SEEK_END)
            stderr_size = stderr_file.tell()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(12000).decode("utf-8", errors="replace")
            stderr = stderr_file.read(12000).decode("utf-8", errors="replace")
        failure = detect_failure(process.returncode, stdout, stderr, timed_out=timed_out)
        if process.returncode == -getattr(signal, "SIGXFSZ", 25):
            failure = {"kind": "output_limit", "error_type": "file-size-limit",
                       "summary": f"process output exceeded {output_limit_bytes} bytes"}
        return {
            "argv": argv,
            "environment": environment,
            "returncode": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "limits": limits_record,
            "output_truncated": stdout_size > 12000 or stderr_size > 12000,
            "failure": failure,
        }
    except subprocess.SubprocessError as exc:
        return {"argv": argv, "environment": environment, "returncode": None, "stdout": "", "stderr": str(exc),
                "timed_out": False, "limits": limits_record,
                "failure": {"kind": "launch_error", "summary": str(exc)}}
    except OSError as exc:
        return {"argv": argv, "environment": environment, "returncode": None, "stdout": "", "stderr": str(exc),
                "timed_out": False, "limits": limits_record,
                "failure": {"kind": "launch_error", "summary": str(exc)}}


def _decode(data):
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def detect_failure(returncode, stdout, stderr, timed_out=False):
    combined = f"{stdout}\n{stderr}"
    for kind, pattern in _SANITIZER_PATTERNS:
        match = pattern.search(combined)
        if match:
            line = combined[match.start():].splitlines()[0][:300]
            error_type = None
            if kind == "address_sanitizer":
                detail = re.search(r"ERROR: AddressSanitizer:\s*([^:\s]+)", combined, re.IGNORECASE)
                error_type = detail.group(1) if detail else "sanitizer-fatal-signal"
            elif kind == "undefined_behavior_sanitizer":
                detail = re.search(r"runtime error:\s*([^:\n]+)", combined, re.IGNORECASE)
                error_type = detail.group(1).strip() if detail else "undefined-behavior"
            elif kind == "stack_protector":
                error_type = "stack-protector-detected-overflow"
            elif kind == "memory_sanitizer":
                error_type = "memory-sanitizer-finding"
            return {"kind": kind, "error_type": error_type, "summary": line}
    if timed_out:
        return {"kind": "timeout", "error_type": "timeout", "summary": "process timed out"}
    if returncode == -getattr(signal, "SIGXFSZ", 25):
        return {"kind": "output_limit", "error_type": "file-size-limit",
                "summary": "process exceeded the configured file/output size limit"}
    if returncode is not None and returncode < 0:
        signal_number = -returncode
        return {"kind": "signal", "error_type": f"signal-{signal_number}", "summary": f"terminated by signal {signal_number}"}
    if "*** stack smashing detected ***" in combined:
        return {"kind": "stack_protector", "error_type": "stack-protector-detected-overflow",
                "summary": "stack protector terminated the program"}
    if "AddressSanitizer:DEADLYSIGNAL" in combined:
        return {"kind": "address_sanitizer", "error_type": "sanitizer-fatal-signal",
                "summary": "AddressSanitizer reported a fatal signal"}
    return None


def find_executable(name):
    return shutil.which(name)
