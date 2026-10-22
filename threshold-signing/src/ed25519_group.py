"""Группа Ed25519 (порядок L) поверх libsodium (PyNaCl). Скаляры - int по модулю L, точки - 32 байта (RFC 8032).
Все входные точки проверяются: на кривой, в основной подгруппе, не малого порядка."""
import os
import nacl.bindings as nb

L = 2 ** 252 + 27742317777372353535851937790883648493
IDENTITY = b"\x01" + b"\x00" * 31


class GroupError(ValueError):
    pass


def ser_scalar(x: int) -> bytes:
    return (x % L).to_bytes(32, "little")


def de_scalar(b: bytes) -> int:
    """Строгое декодирование: ровно 32 байта и значение < L (иначе - неканоническая кодировка)."""
    if len(b) != 32:
        raise GroupError("скаляр должен быть 32 байта")
    x = int.from_bytes(b, "little")
    if x >= L:
        raise GroupError("неканонический скаляр")
    return x


def random_scalar() -> int:
    while True:
        x = int.from_bytes(os.urandom(64), "little") % L
        if x:
            return x


def validate_point(p: bytes, allow_identity: bool = False) -> bytes:
    if not isinstance(p, (bytes, bytearray)) or len(p) != 32:
        raise GroupError("точка должна быть 32 байта")
    p = bytes(p)
    if p == IDENTITY:
        if allow_identity:
            return p
        raise GroupError("нейтральный элемент недопустим")
    if not nb.crypto_core_ed25519_is_valid_point(p):
        raise GroupError("недопустимая точка (не на кривой / не в основной подгруппе / малый порядок)")
    return p


def base_mul(k: int) -> bytes:
    k %= L
    return IDENTITY if k == 0 else nb.crypto_scalarmult_ed25519_base_noclamp(ser_scalar(k))


def point_mul(k: int, p: bytes) -> bytes:
    k %= L
    if k == 0 or p == IDENTITY:
        return IDENTITY
    return nb.crypto_scalarmult_ed25519_noclamp(ser_scalar(k), p)


def point_add(p: bytes, q: bytes) -> bytes:
    if p == IDENTITY:
        return q
    if q == IDENTITY:
        return p
    try:
        return nb.crypto_core_ed25519_add(p, q)
    except RuntimeError:
        return IDENTITY   # p == -q


def point_neg(p: bytes) -> bytes:
    return p if p == IDENTITY else point_mul(L - 1, p)


def point_sub(p: bytes, q: bytes) -> bytes:
    return point_add(p, point_neg(q))


def lagrange_at_zero(ids: list[int], i: int) -> int:
    """Коэффициент Лагранжа λ_i для интерполяции в 0 по множеству идентификаторов ids."""
    if i not in ids or len(set(ids)) != len(ids):
        raise GroupError("плохой набор идентификаторов")
    num = den = 1
    for j in ids:
        if j != i:
            num = num * j % L
            den = den * (j - i) % L
    return num * pow(den, -1, L) % L
