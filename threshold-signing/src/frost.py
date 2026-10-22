"""FROST(Ed25519, SHA-512) по RFC 9591: двухраундовая пороговая подпись Шнорра.
Результат - обычная подпись RFC 8032 (R || S), её проверяет любой Ed25519-верификатор.

Роли: Signer (держит долю и одноразовые nonce), координатор (функции ниже: собирает коммитменты, раздаёт
сообщение, агрегирует). Координатору НЕ доверяется ключ: он видит только публичные значения и доли подписи."""
import hashlib
import os
from dataclasses import dataclass

import ed25519_group as g
from ed25519_group import L, GroupError

CONTEXT = b"FROST-ED25519-SHA512-v1"
MAX_ID = 0xFFFF


class FrostError(Exception):
    pass


class NonceReuseError(FrostError):
    """Попытка использовать одноразовые nonce повторно: это раскрывает долю ключа."""


class InvalidShare(FrostError):
    def __init__(self, identifier: int):
        super().__init__(f"недействительная доля подписи участника {identifier}")
        self.identifier = identifier


# ---- хэши (RFC 9591 §6.1) ----
def _wide(b: bytes) -> int:
    return int.from_bytes(hashlib.sha512(b).digest(), "little") % L


def H1(m): return _wide(CONTEXT + b"rho" + m)            # коэффициенты связывания
def H2(m): return _wide(m)                                # вызов Шнорра; без префикса => совместимо с RFC 8032
def H3(m): return _wide(CONTEXT + b"nonce" + m)           # генерация nonce
def H4(m): return hashlib.sha512(CONTEXT + b"msg" + m).digest()
def H5(m): return hashlib.sha512(CONTEXT + b"com" + m).digest()


# ---- структуры ----
@dataclass(frozen=True)
class KeyShare:
    identifier: int
    secret_share: int            # секретно
    verification_share: bytes    # Y_i = s_i * G
    group_public_key: bytes
    min_signers: int


@dataclass(frozen=True)
class Commitment:
    identifier: int
    hiding: bytes
    binding: bytes


@dataclass(frozen=True)
class SignatureShare:
    identifier: int
    z: int


@dataclass(frozen=True)
class PublicPackage:
    """Всё, что нужно координатору и верификатору (без секретов)."""
    group_public_key: bytes
    verification_shares: dict    # id -> 32 байта
    min_signers: int


def _check_id(i: int):
    if not (isinstance(i, int) and 1 <= i <= MAX_ID):
        raise FrostError(f"идентификатор вне диапазона 1..{MAX_ID}: {i}")


def _encode_commitments(commitments: list[Commitment]) -> bytes:
    return b"".join(g.ser_scalar(c.identifier) + c.hiding + c.binding for c in commitments)


def _prepare(commitments: list[Commitment], min_signers: int) -> list[Commitment]:
    if len(commitments) < min_signers:
        raise FrostError(f"нужно минимум {min_signers} участников, получено {len(commitments)}")
    ids = [c.identifier for c in commitments]
    for i in ids:
        _check_id(i)
    if len(set(ids)) != len(ids):
        raise FrostError("повторяющиеся идентификаторы")
    for c in commitments:
        try:
            g.validate_point(c.hiding); g.validate_point(c.binding)
        except GroupError as e:
            raise FrostError(f"плохой коммитмент участника {c.identifier}: {e}")
    return sorted(commitments, key=lambda c: c.identifier)


def binding_factors(group_pk: bytes, message: bytes, commitments: list[Commitment]) -> dict[int, int]:
    """ρ_i = H1(PK || H4(msg) || H5(список коммитментов) || i): привязка ко ВСЕМУ контексту подписи
    (защита от атаки Дрийверса и др. на параллельные сессии)."""
    prefix = group_pk + H4(message) + H5(_encode_commitments(commitments))
    return {c.identifier: H1(prefix + g.ser_scalar(c.identifier)) for c in commitments}


def group_commitment(commitments: list[Commitment], rhos: dict[int, int]) -> bytes:
    R = g.IDENTITY
    for c in commitments:
        R = g.point_add(R, g.point_add(c.hiding, g.point_mul(rhos[c.identifier], c.binding)))
    return R


def challenge(R: bytes, group_pk: bytes, message: bytes) -> int:
    return H2(R + group_pk + message)


# ---- участник ----
class Signer:
    def __init__(self, key_share: KeyShare):
        self.ks = key_share
        self._pending: dict[tuple[bytes, bytes], tuple[int, int]] = {}

    def commit(self) -> Commitment:
        """Раунд 1. Nonce = H3(случайные 32 байта || секретная доля): даже при сбое ГСЧ nonce зависит от ключа."""
        secret = g.ser_scalar(self.ks.secret_share)
        d, e = H3(os.urandom(32) + secret), H3(os.urandom(32) + secret)
        D, E = g.base_mul(d), g.base_mul(e)
        self._pending[(D, E)] = (d, e)
        return Commitment(self.ks.identifier, D, E)

    def sign(self, message: bytes, commitments: list[Commitment]) -> SignatureShare:
        """Раунд 2. Nonce расходуются один раз, после чего удаляются."""
        cl = _prepare(commitments, self.ks.min_signers)
        mine = [c for c in cl if c.identifier == self.ks.identifier]
        if len(mine) != 1:
            raise FrostError("меня нет в списке коммитментов")
        key = (mine[0].hiding, mine[0].binding)
        if key not in self._pending:
            raise NonceReuseError("коммитмент не выдавался этим участником или его nonce уже использованы")
        d, e = self._pending[key]
        rhos = binding_factors(self.ks.group_public_key, message, cl)
        R = group_commitment(cl, rhos)
        c = challenge(R, self.ks.group_public_key, message)
        lam = g.lagrange_at_zero([x.identifier for x in cl], self.ks.identifier)
        z = (d + e * rhos[self.ks.identifier] + lam * self.ks.secret_share * c) % L
        del self._pending[key]
        return SignatureShare(self.ks.identifier, z)


# ---- координатор / верификатор ----
def verify_share(pkg: PublicPackage, message: bytes, commitments: list[Commitment], share: SignatureShare) -> bool:
    cl = _prepare(commitments, pkg.min_signers)
    rhos = binding_factors(pkg.group_public_key, message, cl)
    R = group_commitment(cl, rhos)
    c = challenge(R, pkg.group_public_key, message)
    ids = [x.identifier for x in cl]
    com = next((x for x in cl if x.identifier == share.identifier), None)
    if com is None or share.identifier not in pkg.verification_shares or not (0 <= share.z < L):
        return False
    lam = g.lagrange_at_zero(ids, share.identifier)
    lhs = g.base_mul(share.z)
    rhs = g.point_add(g.point_add(com.hiding, g.point_mul(rhos[share.identifier], com.binding)),
                      g.point_mul(c * lam, pkg.verification_shares[share.identifier]))
    return lhs == rhs


def aggregate(pkg: PublicPackage, message: bytes, commitments: list[Commitment],
              shares: list[SignatureShare]) -> bytes:
    """Собирает подпись. Проверяет КАЖДУЮ долю: при обмане называет виновного (identifiable abort)."""
    cl = _prepare(commitments, pkg.min_signers)
    if sorted(s.identifier for s in shares) != [c.identifier for c in cl]:
        raise FrostError("доли подписи не соответствуют списку коммитментов")
    for s in shares:
        if not verify_share(pkg, message, cl, s):
            raise InvalidShare(s.identifier)
    rhos = binding_factors(pkg.group_public_key, message, cl)
    R = group_commitment(cl, rhos)
    z = sum(s.z for s in shares) % L
    sig = R + g.ser_scalar(z)
    if not verify(pkg.group_public_key, message, sig):
        raise FrostError("итоговая подпись не прошла проверку")
    return sig


def verify(group_pk: bytes, message: bytes, signature: bytes) -> bool:
    """Собственный верификатор (RFC 8032, без кофактора). Независимая проверка - Ed25519PublicKey.verify в тестах."""
    if len(signature) != 64:
        return False
    try:
        R = g.validate_point(signature[:32], allow_identity=False)
        z = g.de_scalar(signature[32:])
        pk = g.validate_point(group_pk)
    except GroupError:
        return False
    c = H2(R + group_pk + message)
    return g.base_mul(z) == g.point_add(R, g.point_mul(c, pk))


# ---- ключи от доверенного дилера (RFC 9591, Приложение C) ----
def trusted_dealer_keygen(n: int, t: int, secret: int | None = None):
    """Только для тестов/эталона: дилер знает ключ целиком. В проде используйте dkg.py."""
    if not (1 <= t <= n <= MAX_ID):
        raise FrostError("нужно 1 <= t <= n")
    s = secret if secret is not None else g.random_scalar()
    coeffs = [s] + [g.random_scalar() for _ in range(t - 1)]
    pk = g.base_mul(s)
    shares = {}
    for i in range(1, n + 1):
        y = sum(c * pow(i, k, L) for k, c in enumerate(coeffs)) % L
        shares[i] = KeyShare(i, y, g.base_mul(y), pk, t)
    pkg = PublicPackage(pk, {i: ks.verification_share for i, ks in shares.items()}, t)
    return pkg, shares
