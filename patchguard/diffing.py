import re
import subprocess
from pathlib import PurePosixPath


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_LOCATION_RE = re.compile(r"(?P<path>(?:[A-Za-z]:)?[^\r\n:]*?\.(?:c|cc|cpp|h|hpp)):(?P<line>\d+)(?::\d+)?")
_FRAME_PREFIX_RE = re.compile(r"^#\d+\s+\S+\s+in\s+(?P<function>[^\s]+)\s+(?P<path>.+)$")
_HUNK_FUNCTION_RE = re.compile(r"([A-Za-z_~][\w:~.]*)\s*\(")
_FUNCTION_KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "case", "do", "else",
    "defined", "sizeof", "typeof", "alignof",
}


def _relative_diff_text(text, roots):
    """Rewrite absolute no-index paths to source-relative ones.

    Compilers report absolute paths inside each build tree, so a hunk path has to
    be reduced to its source-relative form (``main.c``, ``src/main.c``) before a
    stack-trace location can be matched to it.
    """
    for root in roots:
        normalized = str(root).replace("\\", "/").rstrip("/")
        if not normalized:
            continue
        for variant in {normalized, normalized.lstrip("/")}:
            for marker in ("a", "b"):
                # Git writes the marker and the absolute path with no separator
                # (``a/mnt/...``), but relative roots keep one (``a/bench/...``).
                text = text.replace(f"{marker}{variant}/", f"{marker}/")
                text = text.replace(f"{marker}/{variant}/", f"{marker}/")
    return text


def _marker_path(line):
    """Read the path from a ``+++``/``---`` diff marker line.

    Git appends a tab before an optional timestamp and does not quote paths that
    merely contain spaces, so splitting the line on whitespace truncates them.
    """
    value = line[4:]
    if len(value) >= 2 and value.startswith('"') and value.rstrip().endswith('"'):
        value = value.strip()[1:-1]
        try:
            value = value.encode("latin-1", "backslashreplace").decode("unicode_escape")
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
    return value.split("\t", 1)[0].strip()


def directory_diff(before, after):
    result = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--no-index", "--unified=0", "--", str(before), str(after)],
        capture_output=True, text=True, check=False,
    )
    if result.returncode not in (0, 1):
        return {"text": result.stdout + result.stderr, "hunks": [], "error": f"git diff exited {result.returncode}"}
    text = _relative_diff_text(result.stdout, (before, after))
    return {"text": text, "hunks": parse_hunks(text), "error": None}


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
            current_path = _marker_path(line) or None
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


def _hunk_functions(header):
    """Every identifier that could be the enclosing function named in a hunk header.

    Git echoes the whole enclosing declaration, so an exported symbol such as
    ``CJSON_PUBLIC(char*) cJSON_SetValuestring(...)`` yields the decoration macro
    before the real function name. Keep all candidates instead of only the first.
    """
    context = header.split("@@", 2)[-1]
    names = []
    for match in _HUNK_FUNCTION_RE.finditer(context):
        name = match.group(1)
        if name in _FUNCTION_KEYWORDS or name in names:
            continue
        names.append(name)
    return names


def _hunk_function(header):
    names = _hunk_functions(header)
    return names[0] if names else None


def correlate(diff, stdout, stderr, proximity=12, side="old"):
    locations = []
    for match in _LOCATION_RE.finditer(f"{stdout}\n{stderr}"):
        raw_path = match.group("path").strip()
        frame = _FRAME_PREFIX_RE.match(raw_path)
        locations.append({"path": frame.group("path").strip() if frame else raw_path,
                          "line": int(match.group("line")),
                          "function": frame.group("function") if frame else None})
    matches = []
    for location in locations:
        for hunk in diff.get("hunks", []):
            hunk_path = hunk.get("path") or ""
            if not _matches_changed_path(location["path"], hunk_path):
                continue
            hunk_functions = _hunk_functions(hunk.get("header", ""))
            trace_function = location.get("function")
            hunk_function = next((name for name in hunk_functions if name == trace_function),
                                 hunk_functions[0] if hunk_functions else None)
            same_function = bool(trace_function and trace_function in hunk_functions)
            if trace_function and hunk_functions and not same_function:
                continue
            start_key = "old_start" if side == "old" else "new_start"
            count_key = "old_count" if side == "old" else "new_count"
            start = hunk[start_key]
            count = hunk[count_key]
            line = location["line"]
            if count > 0 and start <= line < start + count:
                relation = "changed_line"
            elif (same_function and
                  max(1, start - proximity) <= line <= start + max(count - 1, 0) + proximity):
                relation = "nearby_line"
            else:
                continue
            matches.append({"location": location, "hunk": hunk["header"],
                            "path": hunk_path, "hunk_function": hunk_function,
                            "same_function": same_function, "relation": relation})
    direct_match = any(match["relation"] == "changed_line" for match in matches)
    return {"related": bool(matches),
            "evidence_level": "direct" if direct_match else ("nearby" if matches else "none"),
            "locations": locations, "matches": matches}
