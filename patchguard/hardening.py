import re
import subprocess


def inspect_elf(executable):
    header = _readelf(["-hW"], executable)
    program_headers = _readelf(["-lW"], executable)
    dynamic = _readelf(["-dW"], executable)
    symbols = _readelf(["-sW"], executable)
    if not all(item["available"] for item in (header, program_headers, dynamic, symbols)):
        return {"available": False, "reason": "readelf is unavailable"}
    if any(item["returncode"] != 0 for item in (header, program_headers, dynamic, symbols)):
        return {"available": False, "reason": "readelf could not inspect the binary"}

    header_text = header["stdout"]
    phdr_text = program_headers["stdout"]
    dynamic_text = dynamic["stdout"]
    symbol_text = symbols["stdout"]
    elf_type = re.search(r"Type:\s+(\S+)", header_text)
    nx_stack = _nx_stack_from_program_headers(phdr_text)
    has_relro = "GNU_RELRO" in phdr_text
    bind_now = "BIND_NOW" in dynamic_text or "NOW" in dynamic_text
    has_canary = "__stack_chk_fail" in symbol_text
    return {
        "available": True,
        "elf_type": elf_type.group(1) if elf_type else None,
        "pie": elf_type is not None and elf_type.group(1) == "DYN",
        "nx_stack": nx_stack,
        "relro": "full" if has_relro and bind_now else ("partial" if has_relro else "none"),
        "stack_canary": has_canary,
        "evidence": {
            "elf_type": _line_with(header_text, "Type:"),
            "nx_stack": _line_with(phdr_text, "GNU_STACK"),
            "relro": _line_with(phdr_text, "GNU_RELRO"),
            "bind_now": _line_with(dynamic_text, "BIND_NOW") or _line_with(dynamic_text, "FLAGS"),
            "stack_canary": _line_with(symbol_text, "__stack_chk_fail"),
        },
    }


def _line_with(text, needle):
    for line in text.splitlines():
        if needle in line:
            return line.strip()[:240]
    return None


def compare_hardening(before, after):
    if not before.get("available") or not after.get("available"):
        return {"available": False, "changes": [], "warnings": [],
                "reason": "one or both ELF reports are unavailable"}

    changes = []
    warnings = []
    for name in ("nx_stack", "pie", "stack_canary"):
        old_value = before.get(name)
        new_value = after.get(name)
        if old_value != new_value:
            change = {"property": name, "before": old_value, "after": new_value,
                      "weakened": old_value is True and new_value is False}
            changes.append(change)
            if change["weakened"]:
                warnings.append(f"{name} was enabled in the baseline and is disabled in the candidate")

    relro_rank = {"none": 0, "partial": 1, "full": 2}
    old_relro = before.get("relro")
    new_relro = after.get("relro")
    if old_relro != new_relro:
        weakened = relro_rank.get(new_relro, -1) < relro_rank.get(old_relro, -1)
        changes.append({"property": "relro", "before": old_relro, "after": new_relro,
                        "weakened": weakened})
        if weakened:
            warnings.append(f"RELRO was reduced from {old_relro} to {new_relro}")

    return {"available": True, "changes": changes, "warnings": warnings}


def _readelf(args, executable):
    try:
        result = subprocess.run(["readelf", *args, str(executable)], capture_output=True, text=True, check=False)
        return {"available": True, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    except OSError:
        return {"available": False, "returncode": None, "stdout": "", "stderr": ""}


def _nx_stack_from_program_headers(program_headers):
    # GNU_STACK has five address/size columns before permissions, then its alignment.
    match = re.search(r"GNU_STACK\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)", program_headers)
    return None if match is None else "E" not in match.group(1)
