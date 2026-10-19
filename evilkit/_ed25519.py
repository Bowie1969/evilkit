"""Pure-Python Ed25519 (RFC 8032) — zero runtime dependencies.

Not fast: a sign or verify costs tens of milliseconds. That is acceptable for
hub coordination traffic (a handful of signed requests per peer per second).
It is NOT appropriate for high-throughput message authentication; use HMAC
for that if you ever need it. This module exists so EvilKit can keep its
zero-runtime-dependency pledge while enrolling peers by public key.

Public surface:
    keypair()                 -> (sk_bytes32, pk_bytes32)
    public_key(sk)            -> pk_bytes32
    sign(msg, sk, pk)         -> sig_bytes64
    verify(sig, msg, pk)      -> bool
    load_sk(path)/save_sk     -> helpers for 32-byte key files, 0600 enforced
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path


_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493


def _pow2(x: int, p: int) -> int:
    while p > 0:
        x = x * x % _Q
        p -= 1
    return x


def _inv(z: int) -> int:
    # Fermat's little theorem; prime modulus _Q.
    return pow(z, _Q - 2, _Q)


_D = -121665 * _inv(121666) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = (_Bx % _Q, _By % _Q, 1, (_Bx * _By) % _Q)
_IDENT = (0, 1, 1, 0)


def _edwards_add(P: tuple, Q: tuple) -> tuple:
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q
    a = (y1 - x1) * (y2 - x2) % _Q
    b = (y1 + x1) * (y2 + x2) % _Q
    c = t1 * 2 * _D * t2 % _Q
    dd = z1 * 2 * z2 % _Q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _edwards_double(P: tuple) -> tuple:
    (x1, y1, z1, _t1) = P
    a = x1 * x1 % _Q
    b = y1 * y1 % _Q
    c = 2 * z1 * z1 % _Q
    h = a + b
    e = h - (x1 + y1) * (x1 + y1) % _Q
    g = a - b
    f = c + g
    return (e * f % _Q, g * h % _Q, f * g % _Q, e * h % _Q)


def _scalarmult(P: tuple, e: int) -> tuple:
    if e == 0:
        return _IDENT
    Q = _scalarmult(P, e // 2)
    Q = _edwards_double(Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


_BPOW: list[tuple] = []


def _build_bpow() -> None:
    P = _B
    for _ in range(253):
        _BPOW.append(P)
        P = _edwards_double(P)


_build_bpow()


def _scalarmult_B(e: int) -> tuple:
    e = e % _L
    P = _IDENT
    for i in range(253):
        if e & 1:
            P = _edwards_add(P, _BPOW[i])
        e >>= 1
    return P


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _encodepoint(P: tuple) -> bytes:
    (x, y, z, _t) = P
    zi = _inv(z)
    x = (x * zi) % _Q
    y = (y * zi) % _Q
    y_bytes = bytearray(y.to_bytes(32, "little"))
    # Set the top bit of the last byte to the low bit of x.
    y_bytes[31] = (y_bytes[31] & 0x7F) | ((x & 1) << 7)
    return bytes(y_bytes)


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _secret_scalar(h: bytes) -> int:
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8  # clear low 3 bits
    a |= 1 << 254  # set bit 254
    return a


def public_key(sk: bytes) -> bytes:
    if len(sk) != 32:
        raise ValueError("secret key must be 32 bytes")
    h = hashlib.sha512(sk).digest()
    a = _secret_scalar(h)
    return _encodepoint(_scalarmult_B(a))


def sign(msg: bytes, sk: bytes, pk: bytes | None = None) -> bytes:
    if len(sk) != 32:
        raise ValueError("secret key must be 32 bytes")
    if pk is None:
        pk = public_key(sk)
    if len(pk) != 32:
        raise ValueError("public key must be 32 bytes")
    h = hashlib.sha512(sk).digest()
    a = _secret_scalar(h)
    r = _hint(h[32:64] + msg)
    R = _scalarmult_B(r)
    enc_R = _encodepoint(R)
    S = (r + _hint(enc_R + pk + msg) * a) % _L
    return enc_R + _encodeint(S)


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _is_on_curve(P: tuple) -> bool:
    (x, y, z, t) = P
    return (
        z % _Q != 0
        and x * y % _Q == z * t % _Q
        and (y * y - x * x - z * z - _D * t * t) % _Q == 0
    )


def _decodepoint(s: bytes) -> tuple:
    if len(s) != 32:
        raise ValueError("point length must be 32 bytes")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = _Q - x
    P = (x, y, 1, (x * y) % _Q)
    if not _is_on_curve(P):
        raise ValueError("point is not on curve")
    return P


def verify(sig: bytes, msg: bytes, pk: bytes) -> bool:
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
    except ValueError:
        return False
    S = _decodeint(sig[32:64])
    if S >= _L:
        return False
    h = _hint(sig[:32] + pk + msg)
    P = _scalarmult_B(S)
    Q = _edwards_add(R, _scalarmult(A, h))
    (x1, y1, z1, _t1) = P
    (x2, y2, z2, _t2) = Q
    if not _is_on_curve(P) or not _is_on_curve(Q):
        return False
    if (x1 * z2 - x2 * z1) % _Q != 0:
        return False
    if (y1 * z2 - y2 * z1) % _Q != 0:
        return False
    return True


def keypair() -> tuple[bytes, bytes]:
    sk = secrets.token_bytes(32)
    return sk, public_key(sk)


def save_sk(path: Path, sk: bytes) -> None:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(sk)


def load_sk(path: Path) -> bytes:
    path = Path(path).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"secret key file is missing or a symlink: {path}")
    if path.stat().st_mode & 0o077:
        raise ValueError(f"secret key file must be chmod 600: {path}")
    data = path.read_bytes()
    if len(data) != 32:
        raise ValueError(f"secret key file must be exactly 32 bytes: {path}")
    return data
