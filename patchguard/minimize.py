def minimize_bytes(original, reproduces, max_attempts=32):
    """Chunk-deletion minimization; the predicate must preserve the finding class."""
    current = original
    attempts = 0
    granularity = 2
    while len(current) >= 2 and attempts < max_attempts:
        chunk = max(1, (len(current) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(current), chunk):
            candidate = current[:start] + current[start + chunk:]
            attempts += 1
            if candidate and reproduces(candidate):
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
            if attempts >= max_attempts:
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return current, attempts
