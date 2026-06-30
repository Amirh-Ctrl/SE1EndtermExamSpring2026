from __future__ import annotations

import hmac
import struct


class AuthenticationFailed(ValueError):
    """Raised when an AEAD tag cannot be verified."""


def _rotl32(value: int, amount: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << amount) & 0xFFFFFFFF) | (value >> (32 - amount))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("ChaCha20 keys must be 32 bytes.")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 nonces must be 12 bytes.")

    constants = struct.unpack("<4I", b"expand 32-byte k")
    key_words = struct.unpack("<8I", key)
    nonce_words = struct.unpack("<3I", nonce)
    initial = list(constants + key_words + (counter & 0xFFFFFFFF,) + nonce_words)
    working = initial.copy()

    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    final = [(value + initial[index]) & 0xFFFFFFFF for index, value in enumerate(working)]
    return struct.pack("<16I", *final)


def _chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int) -> bytes:
    output = bytearray()
    for offset in range(0, len(data), 64):
        block = chacha20_block(key, counter, nonce)
        counter = (counter + 1) & 0xFFFFFFFF
        chunk = data[offset : offset + 64]
        output.extend(byte ^ block[index] for index, byte in enumerate(chunk))
    return bytes(output)


def _poly1305_mac(message: bytes, one_time_key: bytes) -> bytes:
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 one-time keys must be 32 bytes.")

    r = int.from_bytes(one_time_key[:16], "little")
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(one_time_key[16:], "little")
    modulus = (1 << 130) - 5
    accumulator = 0

    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        number = int.from_bytes(block + b"\x01", "little")
        accumulator = ((accumulator + number) * r) % modulus

    tag = (accumulator + s) % (1 << 128)
    return tag.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"\x00" * ((16 - (len(data) % 16)) % 16)


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = _chacha20_xor(key, nonce, plaintext, counter=1)
    tag = _poly1305_mac(_mac_data(aad, ciphertext), one_time_key)
    return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    expected_tag = _poly1305_mac(_mac_data(aad, ciphertext), one_time_key)
    if not hmac.compare_digest(expected_tag, tag):
        raise AuthenticationFailed("Message authentication failed.")
    return _chacha20_xor(key, nonce, ciphertext, counter=1)

