import hashlib


def minimize_bytes(original, reproduces, max_attempts=200):
    """Delta-debugging style chunk deletion; the predicate preserves the finding."""
    current = original
    attempts = 0
    seen = {hashlib.sha256(current).digest()}
    chunk = max(1, len(current) // 2)
    while len(current) > 1 and attempts < max_attempts and chunk >= 1:
        reduced = False
        start = 0
        while start < len(current) and attempts < max_attempts:
            candidate = current[:start] + current[start + chunk:]
            if not candidate:
                start += chunk
                continue
            digest = hashlib.sha256(candidate).digest()
            if digest in seen:
                start += chunk
                continue
            seen.add(digest)
            attempts += 1
            if reproduces(candidate):
                current = candidate
                reduced = True
                chunk = max(1, min(chunk, len(current) // 2)) if len(current) > 1 else 0
            else:
                start += chunk
        if not reduced:
            if chunk == 1:
                break
            chunk = max(1, chunk // 2)
    return current, attempts
