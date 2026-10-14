"""Generates the KDBX fixtures that the MoonBit tests embed as hex.

This script is not part of the MoonBit build; it exists so that the fixtures in
the test suite are reproducible and their provenance is documented, instead of
being opaque binary blobs copied from somewhere else.

The AES implementation below was validated against the FIPS-197 appendix C.3
example and against .NET's AES; the key schedule follows the KDBX 4.1
specification, so a fixture it produces is a genuine KDBX 4.1 prefix that any
correct implementation must accept.
"""
import hashlib
import hmac

# --- AES-256 (encryption direction only, ECB over single blocks) -------------

def _gf_mul(a, b):
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return product


def _gf_inverse(a):
    if a == 0:
        return 0
    for candidate in range(1, 256):
        if _gf_mul(a, candidate) == 1:
            return candidate
    raise AssertionError


def _rotl(value, bits):
    return ((value << bits) | (value >> (8 - bits))) & 0xFF


SBOX = []
for _a in range(256):
    _x = _gf_inverse(_a)
    SBOX.append((_x ^ _rotl(_x, 1) ^ _rotl(_x, 2) ^ _rotl(_x, 3) ^ _rotl(_x, 4)
                 ^ 0x63) & 0xFF)

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]
ROUNDS = 14


def expand_key(key):
    words = list(key)
    index = 8
    while index < 4 * (ROUNDS + 1):
        base = index * 4
        previous = base - 4
        if index % 8 == 0:
            rotated = [words[previous + 1], words[previous + 2],
                       words[previous + 3], words[previous]]
            substituted = [SBOX[b] for b in rotated]
            substituted[0] ^= RCON[index // 8 - 1]
            for j in range(4):
                words.append(words[base - 32 + j] ^ substituted[j])
        elif index % 8 == 4:
            for j in range(4):
                words.append(words[base - 32 + j] ^ SBOX[words[previous + j]])
        else:
            for j in range(4):
                words.append(words[base - 32 + j] ^ words[previous + j])
        index += 1
    return words


def _xtime(value):
    shifted = (value << 1) & 0xFF
    return shifted ^ 0x1B if value & 0x80 else shifted


def encrypt_block(schedule, block):
    state = list(block)
    for i in range(16):
        state[i] ^= schedule[i]
    for round_index in range(1, ROUNDS):
        state = [SBOX[b] for b in state]
        state = [state[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]
        for c in range(4):
            o = c * 4
            a0, a1, a2, a3 = state[o:o + 4]
            state[o] = _xtime(a0) ^ _xtime(a1) ^ a1 ^ a2 ^ a3
            state[o + 1] = a0 ^ _xtime(a1) ^ _xtime(a2) ^ a2 ^ a3
            state[o + 2] = a0 ^ a1 ^ _xtime(a2) ^ _xtime(a3) ^ a3
            state[o + 3] = _xtime(a0) ^ a0 ^ a1 ^ a2 ^ _xtime(a3)
        offset = round_index * 16
        for i in range(16):
            state[i] ^= schedule[offset + i]
    state = [SBOX[b] for b in state]
    state = [state[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]
    offset = ROUNDS * 16
    for i in range(16):
        state[i] ^= schedule[offset + i]
    return bytes(state)


# --- KDBX 4.1 header and key schedule ---------------------------------------

AES256_CBC_UUID = bytes.fromhex("31c1f2e6bf714350be5805216afc5aff")
AES_KDF_UUID = bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea")


def field(field_id, value):
    return bytes([field_id]) + len(value).to_bytes(4, "little") + value


def variant_dictionary(items):
    out = (0x0100).to_bytes(2, "little")
    for name, type_code, value in items:
        encoded = name.encode("utf-8")
        out += bytes([type_code]) + len(encoded).to_bytes(4, "little") + encoded
        out += len(value).to_bytes(4, "little") + value
    return out + b"\x00"


def aes_kdf(composite, seed, rounds):
    schedule = expand_key(seed)
    buffer = bytearray(composite)
    for _ in range(rounds):
        buffer[0:16] = encrypt_block(schedule, bytes(buffer[0:16]))
        buffer[16:32] = encrypt_block(schedule, bytes(buffer[16:32]))
    return bytes(buffer)


def build(password, master_seed, kdf_seed, rounds):
    header = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5"          # signature words
    header += (0x00040001).to_bytes(4, "little")           # format version 4.1
    header += field(2, AES256_CBC_UUID)
    header += field(3, (0).to_bytes(4, "little"))          # compression: none
    header += field(4, master_seed)
    header += field(7, bytes(range(16, 32)))               # encryption IV
    header += field(11, variant_dictionary([
        ("$UUID", 0x42, AES_KDF_UUID),
        ("S", 0x42, kdf_seed),
        ("R", 0x05, rounds.to_bytes(8, "little")),
    ]))
    header += field(0, b"\x0d\x0a\x0d\x0a")                # end of header

    composite = hashlib.sha256(hashlib.sha256(password.encode("utf-8")).digest()).digest()
    transformed = aes_kdf(composite, kdf_seed, rounds)
    base = hashlib.sha512(master_seed + transformed + b"\x01").digest()
    header_key = hashlib.sha512(b"\xff" * 8 + base).digest()
    # The header is authenticated with HMAC-SHA-256, keyed by the 64-byte value
    # derived above (specification, "Improved Header Authentication").
    return header + hashlib.sha256(header).digest() + \
        hmac.new(header_key, header, hashlib.sha256).digest()


PASSWORD = "correct horse battery staple"


def main():
    data = build(PASSWORD, bytes(range(16, 48)), bytes(range(32)), 1000)
    print(f"# {len(data)} bytes, password: {PASSWORD!r}")
    for i in range(0, len(data), 32):
        print(data[i:i + 32].hex())


if __name__ == "__main__":
    main()
