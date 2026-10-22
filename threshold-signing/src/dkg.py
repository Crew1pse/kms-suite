"""Распределённая генерация ключа (DKG) для FROST: Pedersen DKG с доказательством владения (FROST paper, Fig. 1).
Доверенного дилера нет: полный секретный ключ не существует ни у кого и никогда.

Раунд 1: каждый участник рассылает ВСЕМ коммитменты φ_{i,k} = a_{i,k}·G и доказательство знания a_{i,0} (Шнорр, PoK).
Раунд 2: каждый шлёт КАЖДОМУ участнику l его долю f_i(l) по защищённому каналу (аутентификация + шифрование!).
Финал:  s_l = Σ_i f_i(l); групповой ключ Y = Σ_i φ_{i,0}; доли проверяются по коммитментам (Feldman)."""
import hashlib
from dataclasses import dataclass

import ed25519_group as g
from ed25519_group import L, GroupError
from frost import CONTEXT, KeyShare, PublicPackage, MAX_ID


class DKGError(Exception):
    def __init__(self, culprit: int | None, reason: str):
        super().__init__(f"DKG: участник {culprit}: {reason}")
        self.culprit, self.reason = culprit, reason


@dataclass(frozen=True)
class Round1Package:
    identifier: int
    commitments: tuple          # (φ_0, ..., φ_{t-1}), 32 байта каждый
    pok_R: bytes
    pok_mu: int


@dataclass(frozen=True)
class Round2Package:
    sender: int
    receiver: int
    share: int                  # СЕКРЕТНО: только по защищённому каналу


def _pok_challenge(session: bytes, identifier: int, phi0: bytes, R: bytes) -> int:
    h = hashlib.sha512(CONTEXT + b"dkg-pok" + len(session).to_bytes(4, "big") + session +
                       g.ser_scalar(identifier) + phi0 + R).digest()
    return int.from_bytes(h, "little") % L


def _eval_commitments(commitments, x: int) -> bytes:
    """Σ_k φ_k · x^k - открытое значение многочлена в точке x (в экспоненте)."""
    acc, xp = g.IDENTITY, 1
    for phi in commitments:
        acc = g.point_add(acc, g.point_mul(xp, phi))
        xp = xp * x % L
    return acc


class DKGParticipant:
    def __init__(self, identifier: int, n: int, t: int, session: bytes):
        """session - уникальный идентификатор запуска DKG (привязывает PoK к сессии: защита от переиспользования)."""
        if not (1 <= identifier <= n <= MAX_ID and 1 <= t <= n):
            raise DKGError(identifier, "параметры вне диапазона")
        if not session:
            raise DKGError(identifier, "нужен непустой идентификатор сессии")
        self.id, self.n, self.t, self.session = identifier, n, t, session
        self._poly: list[int] | None = None
        self._r1: dict[int, Round1Package] | None = None

    # ---- раунд 1 ----
    def round1(self) -> Round1Package:
        if self._poly is not None:
            raise DKGError(self.id, "round1 уже выполнен")
        self._poly = [g.random_scalar() for _ in range(self.t)]
        commitments = tuple(g.base_mul(a) for a in self._poly)
        k = g.random_scalar()
        R = g.base_mul(k)
        c = _pok_challenge(self.session, self.id, commitments[0], R)
        return Round1Package(self.id, commitments, R, (k + self._poly[0] * c) % L)

    def _verify_r1(self, pkg: Round1Package):
        if not (1 <= pkg.identifier <= self.n):
            raise DKGError(pkg.identifier, "идентификатор вне диапазона")
        if len(pkg.commitments) != self.t:
            raise DKGError(pkg.identifier, f"ожидалось {self.t} коммитментов, получено {len(pkg.commitments)}")
        try:
            for p in pkg.commitments:
                g.validate_point(p)
            g.validate_point(pkg.pok_R)
        except GroupError as e:
            raise DKGError(pkg.identifier, f"недопустимая точка: {e}")
        if not (0 <= pkg.pok_mu < L):
            raise DKGError(pkg.identifier, "неканоническое μ")
        c = _pok_challenge(self.session, pkg.identifier, pkg.commitments[0], pkg.pok_R)
        if g.base_mul(pkg.pok_mu) != g.point_add(pkg.pok_R, g.point_mul(c, pkg.commitments[0])):
            raise DKGError(pkg.identifier, "доказательство владения (PoK) недействительно")

    # ---- раунд 2 ----
    def round2(self, r1_packages: list[Round1Package]) -> list[Round2Package]:
        if self._poly is None or self._r1 is not None:
            raise DKGError(self.id, "round2 вызван в неверном порядке")
        ids = sorted(p.identifier for p in r1_packages)
        if ids != list(range(1, self.n + 1)):
            raise DKGError(None, f"нужны пакеты ровно от участников 1..{self.n}, получено {ids}")
        for p in r1_packages:
            self._verify_r1(p)              # включая собственный: ловит ошибку в нашем же пакете
        self._r1 = {p.identifier: p for p in r1_packages}
        out = []
        for l in range(1, self.n + 1):
            y = sum(a * pow(l, k, L) for k, a in enumerate(self._poly)) % L
            out.append(Round2Package(self.id, l, y))
        self._poly = None                   # многочлен больше не нужен: удаляем
        return out

    # ---- финализация ----
    def finalize(self, r2_for_me: list[Round2Package]) -> tuple[KeyShare, PublicPackage]:
        if self._r1 is None:
            raise DKGError(self.id, "finalize вызван до round2")
        senders = sorted(p.sender for p in r2_for_me)
        if senders != list(range(1, self.n + 1)) or any(p.receiver != self.id for p in r2_for_me):
            raise DKGError(None, "нужны доли ровно от всех участников, адресованные мне")
        s = 0
        for p in r2_for_me:
            if not (0 <= p.share < L):
                raise DKGError(p.sender, "неканоническая доля")
            if g.base_mul(p.share) != _eval_commitments(self._r1[p.sender].commitments, self.id):
                raise DKGError(p.sender, "доля не соответствует опубликованным коммитментам (Feldman)")
            s = (s + p.share) % L
        group_pk = g.IDENTITY
        for p in self._r1.values():
            group_pk = g.point_add(group_pk, p.commitments[0])
        group_pk = g.validate_point(group_pk)
        # публично вычислимые проверочные доли всех участников: Y_l = Σ_j Σ_k φ_{j,k} l^k
        vshares = {}
        for l in range(1, self.n + 1):
            acc = g.IDENTITY
            for p in self._r1.values():
                acc = g.point_add(acc, _eval_commitments(p.commitments, l))
            vshares[l] = acc
        if g.base_mul(s) != vshares[self.id]:
            raise DKGError(None, "итоговая доля не совпадает с проверочной (внутренняя ошибка)")
        pkg = PublicPackage(group_pk, vshares, self.t)
        return KeyShare(self.id, s, vshares[self.id], group_pk, self.t), pkg
