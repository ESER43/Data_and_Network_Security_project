import random


def mutate(data, rng):
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=[];_:-\x00\xff"
    if not data:
        return bytes([rng.choice(alphabet)])
    operation = rng.randrange(3)
    if operation == 0 and len(data) > 1:
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randint(1, max(1, len(data) // 4)))
        return data[:start] + data[end:]
    if operation == 1:
        start = rng.randrange(len(data) + 1)
        inserted = bytes(rng.choice(alphabet) for _ in range(rng.randint(1, 4)))
        return data[:start] + inserted + data[start:]
    start = rng.randrange(len(data))
    changed = bytearray(data)
    changed[start] = rng.choice(alphabet)
    return bytes(changed)
