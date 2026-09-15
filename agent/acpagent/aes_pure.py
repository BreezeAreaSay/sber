"""A small, dependency-free AES (decrypt paths for ECB / CBC / CTR).

The container ships `cryptography`, but its native binding has failed to load in some
environments and raised a Rust PanicException that a normal `except Exception` does not
catch. Rather than gamble the whole CTF solver on that binding, AES is implemented here
in pure Python. The data a challenge hides is tiny, so speed is irrelevant, and this
cannot be defeated by a missing or broken module.

Only decryption is needed for solving, plus block encryption because CTR decrypt is
built from it.
"""

_SBOX = None
_INV_SBOX = None
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D, 0x9A)


def _build_sboxes():
    global _SBOX, _INV_SBOX
    if _SBOX is not None:
        return
    p = q = 1
    sbox = [0] * 256
    # generate the S-box via the standard log/exp construction over GF(2^8)
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        q &= 0xFF
        xformed = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (xformed ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    _SBOX, _INV_SBOX = sbox, inv


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)


def _mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        b >>= 1
        a = _xtime(a)
    return res & 0xFF


def _key_expansion(key):
    _build_sboxes()
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
    return words, nr


def _add_round_key(state, words, rnd):
    for c in range(4):
        w = words[rnd * 4 + c]
        for r in range(4):
            state[r][c] ^= w[r]


def _inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = _INV_SBOX[state[r][c]]


def _inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def _inv_mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
        state[1][c] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
        state[2][c] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
        state[3][c] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)


def _sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
        state[1][c] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
        state[2][c] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
        state[3][c] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])


def _to_state(block):
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _from_state(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


def _encrypt_block(block, words, nr):
    state = _to_state(block)
    _add_round_key(state, words, 0)
    for rnd in range(1, nr):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, words, rnd)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, words, nr)
    return _from_state(state)


def _decrypt_block(block, words, nr):
    state = _to_state(block)
    _add_round_key(state, words, nr)
    for rnd in range(nr - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, words, rnd)
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, words, 0)
    return _from_state(state)


def decrypt_ecb(key, data):
    words, nr = _key_expansion(key)
    return b"".join(_decrypt_block(data[i:i + 16], words, nr) for i in range(0, len(data) - len(data) % 16, 16))


def decrypt_cbc(key, iv, data):
    words, nr = _key_expansion(key)
    out, prev = [], iv
    for i in range(0, len(data) - len(data) % 16, 16):
        block = data[i:i + 16]
        dec = _decrypt_block(block, words, nr)
        out.append(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = block
    return b"".join(out)


def decrypt_ctr(key, nonce, data):
    words, nr = _key_expansion(key)
    counter = int.from_bytes((nonce + b"\x00" * 16)[:16], "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = _encrypt_block((counter).to_bytes(16, "big"), words, nr)
        chunk = data[i:i + 16]
        out.extend(a ^ b for a, b in zip(chunk, ks))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


def encrypt_ecb(key, data):
    words, nr = _key_expansion(key)
    return b"".join(_encrypt_block(data[i:i + 16], words, nr) for i in range(0, len(data), 16))
