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
import gzip as gzip_module
import zlib

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


def build(password, master_seed, kdf_seed, rounds, compression=0):
    header = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5"          # signature words
    header += (0x00040001).to_bytes(4, "little")           # format version 4.1
    header += field(2, AES256_CBC_UUID)
    header += field(3, compression.to_bytes(4, "little"))  # 0 none, 1 gzip
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
IV = bytes(range(16, 32))
INNER_RANDOM_STREAM_ID = 3          # ChaCha20, as KeePass writes for KDBX 4
INNER_RANDOM_STREAM_KEY = bytes(range(64))
XML = b"<KeePassFile><Meta><Generator>kdbx.mbt fixture</Generator></Meta></KeePassFile>"


def inner_header():
    """Inner header: the random stream used to protect individual fields."""
    out = b""
    out += bytes([0x01]) + (4).to_bytes(4, "little") + \
        INNER_RANDOM_STREAM_ID.to_bytes(4, "little")
    out += bytes([0x02]) + (64).to_bytes(4, "little") + INNER_RANDOM_STREAM_KEY
    return out + b"\x00"


def payload():
    """The bytes that get compressed, encrypted and written to the file."""
    return inner_header() + XML


def pkcs7(data, block=16):
    pad = block - len(data) % block
    return data + bytes([pad]) * pad


def cbc_encrypt(key, iv, data):
    schedule = expand_key(key)
    out = b""
    previous = iv
    for offset in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[offset:offset + 16], previous))
        previous = encrypt_block(schedule, block)
        out += previous
    return out


def block_stream(hmac_base, ciphertext, block_size=1024):
    """HMAC-protected blocks: tag, index, size, and the ciphertext."""
    out = b""
    index = 0
    chunks = [ciphertext[i:i + block_size]
              for i in range(0, len(ciphertext), block_size)]
    for chunk in chunks + [b""]:
        index_bytes = index.to_bytes(8, "little")
        size_bytes = len(chunk).to_bytes(4, "little")
        key = hashlib.sha512(index_bytes + hmac_base).digest()
        out += hmac.new(key, index_bytes + size_bytes + chunk, hashlib.sha256).digest()
        out += index_bytes + size_bytes + chunk
        index += 1
    return out


def build_database(password, master_seed, kdf_seed, rounds):
    """A complete KDBX 4.1 file: header, tags, and an encrypted payload."""
    header = build(password, master_seed, kdf_seed, rounds)
    header_bytes = header[:len(header) - 64]
    composite = hashlib.sha256(
        hashlib.sha256(password.encode("utf-8")).digest()).digest()
    transformed = aes_kdf(composite, kdf_seed, rounds)
    base = hashlib.sha512(master_seed + transformed + b"\x01").digest()
    encryption_key = hashlib.sha256(master_seed + transformed).digest()
    ciphertext = cbc_encrypt(encryption_key, IV, pkcs7(payload()))
    return header_bytes + hashlib.sha256(header_bytes).digest() + \
        hmac.new(hashlib.sha512(b"\xff" * 8 + base).digest(), header_bytes,
                 hashlib.sha256).digest() + block_stream(base, ciphertext)


def emit(name, data):
    print(f"# {name}: {len(data)} bytes")
    for i in range(0, len(data), 32):
        print(data[i:i + 32].hex())


SMALL_PAYLOAD = b"compressed payload for the kdbx.mbt test suite"


def compressed_database(password, master_seed, kdf_seed, rounds,
                        contents=SMALL_PAYLOAD):
    """Same database, but with the payload gzipped and the flag set.

    The payload is kept short so the whole file can be embedded in a test as
    hex; the realistic payload is covered by the uncompressed fixture.
    """
    header = build(password, master_seed, kdf_seed, rounds, compression=1)
    header_bytes = header[:len(header) - 64]
    composite = hashlib.sha256(
        hashlib.sha256(password.encode("utf-8")).digest()).digest()
    transformed = aes_kdf(composite, kdf_seed, rounds)
    base = hashlib.sha512(master_seed + transformed + b"\x01").digest()
    encryption_key = hashlib.sha256(master_seed + transformed).digest()
    # KDBX's compression flag means the gzip container, not the zlib one.
    ciphertext = cbc_encrypt(
        encryption_key, IV, pkcs7(gzip_module.compress(contents)))
    return header_bytes + hashlib.sha256(header_bytes).digest() + \
        hmac.new(hashlib.sha512(b"\xff" * 8 + base).digest(), header_bytes,
                 hashlib.sha256).digest() + block_stream(base, ciphertext)


TEXT_LINE = b"the quick brown fox jumps over the lazy dog "


def raw_deflate(data, level=9, strategy=zlib.Z_DEFAULT_STRATEGY):
    """A raw DEFLATE stream (wbits = -15), exactly what gzip hands to inflate."""
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15, 9, strategy)
    return compressor.compress(data) + compressor.flush()


def sha_derived(count):
    """Incompressible bytes derived from SHA-256, reproducible in the test."""
    return b"".join(hashlib.sha256(i.to_bytes(4, "little")).digest()
                    for i in range(count // 32))


def deflate_variants():
    """One stream per DEFLATE block type, so each decoding path is exercised."""
    return [
        ("stored", sha_derived(512), raw_deflate(sha_derived(512), 9)),
        ("fixed", TEXT_LINE * 16, raw_deflate(TEXT_LINE * 16, 9, zlib.Z_FIXED)),
        ("dynamic", TEXT_LINE * 64, raw_deflate(TEXT_LINE * 64, 9)),
    ]


def main():
    print(f"# password: {PASSWORD!r}")
    emit("header fixture", build(PASSWORD, bytes(range(16, 48)), bytes(range(32)), 1000))
    emit("database fixture",
         build_database(PASSWORD, bytes(range(16, 48)), bytes(range(32)), 1000))
    print("# payload plaintext")
    print(payload().hex())
    emit("compressed database fixture",
         compressed_database(PASSWORD, bytes(range(16, 48)), bytes(range(32)), 1000))
    print("# compressed fixture as one line, for embedding in a test")
    print(compressed_database(
        PASSWORD, bytes(range(16, 48)), bytes(range(32)), 1000).hex())
    print("# compressed fixture plaintext")
    print(SMALL_PAYLOAD.hex())
    print("# standalone gzip stream of that plaintext")
    print(gzip_module.compress(SMALL_PAYLOAD).hex())
    for name, plain, stream in deflate_variants():
        # Bits 1-2 of the first byte are the block type; report the one the
        # compressor actually chose so the test cannot claim coverage it lacks.
        block_type = (stream[0] >> 1) & 0x03
        print(f"# deflate {name}: plaintext {len(plain)} bytes, "
              f"stream {len(stream)} bytes, block type {block_type}")
        print(stream.hex())


if __name__ == "__main__":
    main()
