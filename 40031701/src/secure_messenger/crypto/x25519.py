from __future__ import annotations

import secrets

P = 2**255 - 19
A24 = 121665
BASE_POINT = (9).to_bytes(32, "little")


def generate_private_key() -> bytes:
    return secrets.token_bytes(32)


def clamp_scalar(private_key: bytes) -> bytes:
    if len(private_key) != 32:
        raise ValueError("X25519 private keys must be 32 bytes.")
    scalar = bytearray(private_key)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)


def _cswap(swap: int, x2: int, x3: int) -> tuple[int, int]:
    mask = -swap
    dummy = mask & (x2 ^ x3)
    return x2 ^ dummy, x3 ^ dummy


def x25519(private_key: bytes, public_key: bytes) -> bytes:
    if len(public_key) != 32:
        raise ValueError("X25519 public keys must be 32 bytes.")

    k = int.from_bytes(clamp_scalar(private_key), "little")
    u = int.from_bytes(public_key, "little") & ((1 << 255) - 1)

    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0

    for bit_index in reversed(range(255)):
        bit = (k >> bit_index) & 1
        swap ^= bit
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        swap = bit

        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = ((da + cb) ** 2) % P
        z3 = (x1 * ((da - cb) ** 2)) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + A24 * e)) % P

    x2, x3 = _cswap(swap, x2, x3)
    z2, z3 = _cswap(swap, z2, z3)
    result = (x2 * pow(z2, P - 2, P)) % P
    return result.to_bytes(32, "little")


def public_key_from_private(private_key: bytes) -> bytes:
    return x25519(private_key, BASE_POINT)

