import re
import shlex
import subprocess
from pathlib import PurePosixPath


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_LOCATION_RE = re.compile(r"((?:[A-Za-z]:)?[^\r\n:]*?\.(?:c|cc|cpp|h|hpp)):(\d+)(?::\d+)?")


def directory_diff(before, after):
    result = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--no-index", "--unified=0", "--", str(before), str(after)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode not in (0, 1):
        return {"text": result.stdout + result.stderr, "hunks": [], "error": f"git diff exited {result.returncode}"}
    return {"text": result.stdout, "hunks": parse_hunks(result.stdout), "error": None}


def revision_diff(repository, before_ref, after_ref):
    result = subprocess.run(
        ["git", "-C", str(repository), "diff", "--no-ext-diff", "--unified=0",
         before_ref, after_ref, "--"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        return {"text": result.stdout + result.stderr, "hunks": [], "error": f"git diff exited {result.returncode}"}
    return {"text": result.stdout, "hunks": parse_hunks(result.stdout), "error": None}


def parse_hunks(diff_text):
    hunks = []
    current_path = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            try:
                fields = shlex.split(line, posix=True)
            except ValueError:
                fields = line.split(maxsplit=1)
            current_path = fields[1] if len(fields) > 1 else None
            if current_path == "/dev/null":
                current_path = None
            elif current_path and current_path.startswith("b/"):
                current_path = current_path[2:]
            if current_path:
                current_path = current_path.replace("\\", "/")
        elif line.startswith("diff --git "):
            # The next +++ line gives the path used for both source snapshots.
            current_path = None
        elif line.startswith("@@ "):
            match = _HUNK_RE.match(line)
            if not match:
                continue
            old_start, old_count, new_start, new_count = match.groups()
            hunks.append({
                "path": current_path,
                "old_start": int(old_start),
                "old_count": int(old_count) if old_count is not None else 1,
                "new_start": int(new_start),
                "new_count": int(new_count) if new_count is not None else 1,
                "header": line,
            })
    return hunks


def _path_parts(path):
    normalized = str(path).replace("\\", "/")
    return tuple(part for part in PurePosixPath(normalized).parts if part not in {"/", "."})


def _matches_changed_path(source_path, changed_path):
    source_parts = _path_parts(source_path)
    changed_parts = _path_parts(changed_path)
    return bool(changed_parts) and len(changed_parts) <= len(source_parts) and (
        source_parts[-len(changed_parts):] == changed_parts
    )


def correlate(diff, stdout, stderr, proximity=12, side="old"):
    locations = []
    for match in _LOCATION_RE.finditer(f"{stdout}\n{stderr}"):
        locations.append({"path": match.group(1), "line": int(match.group(2))})
    matches = []
    for location in locations:
        for hunk in diff.get("hunks", []):
            hunk_path = hunk.get("path") or ""
            if not _matches_changed_path(location["path"], hunk_path):
                continue
            start_key = "old_start" if side == "old" else "new_start"
            count_key = "old_count" if side == "old" else "new_count"
            start = hunk[start_key]
            count = hunk[count_key]
            line = location["line"]
            if count > 0 and start <= line < start + count:
                relation = "changed_line"
            elif max(1, start - proximity) <= line <= start + max(count - 1, 0) + proximity:
                relation = "nearby_line"
            else:
                continue
            matches.append({"location": location, "hunk": hunk["header"],
                            "path": hunk_path, "relation": relation})
    direct_match = any(match["relation"] == "changed_line" for match in matches)
    return {"related": bool(matches),
            "evidence_level": "direct" if direct_match else ("nearby" if matches else "none"),
            "locations": locations, "matches": matches}
