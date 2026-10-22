import random
from itertools import combinations
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import ed25519_group as g
import frost
from dkg import DKGParticipant, DKGError, Round1Package, Round2Package
from helpers import run_dkg, sign_with


@pytest.mark.parametrize("n,t", [(1, 1), (2, 2), (3, 2), (3, 3), (5, 3), (7, 4)])
def test_dkg_produces_a_working_threshold_key(n, t):
    shares, pkgs, *_ = run_dkg(n, t)
    pks = {p.group_public_key for p in pkgs.values()}
    assert len(pks) == 1                                              # все участники пришли к одному ключу
    pkg = pkgs[1]
    assert all(pkgs[i].verification_shares == pkg.verification_shares for i in pkgs)
    assert all(g.base_mul(shares[i].secret_share) == pkg.verification_shares[i] for i in shares)
    msg = b"signed without any dealer"
    for size in range(t, n + 1):
        for ids in list(combinations(range(1, n + 1), size))[:6]:
            sig = sign_with(pkg, shares, ids, msg)
            Ed25519PublicKey.from_public_bytes(pkg.group_public_key).verify(sig, msg)    # независимый верификатор


def test_group_secret_exists_only_implicitly():
    n, t = 5, 3
    shares, pkgs, *_ = run_dkg(n, t)
    pk = pkgs[1].group_public_key
    for ids in ([1, 2, 3], [2, 4, 5], [1, 3, 5]):
        sk = sum(g.lagrange_at_zero(ids, i) * shares[i].secret_share for i in ids) % g.L
        assert g.base_mul(sk) == pk                                   # любые t долей согласуются с одним ключом
    sk2 = sum(g.lagrange_at_zero([1, 2], i) * shares[i].secret_share for i in [1, 2]) % g.L
    assert g.base_mul(sk2) != pk                                      # t-1 долей - не ключ
    assert all(s.secret_share != 0 for s in shares.values())


def test_group_key_is_sum_of_constant_term_commitments():
    shares, pkgs, parts, r1, r2 = run_dkg(4, 3)
    acc = g.IDENTITY
    for p in r1: acc = g.point_add(acc, p.commitments[0])
    assert acc == pkgs[1].group_public_key


def test_polynomial_erased_after_round2_and_runs_are_independent():
    shares, pkgs, parts, *_ = run_dkg(3, 2)
    assert all(p._poly is None for p in parts.values())
    a, _, *_ = run_dkg(3, 2); b, _, *_ = run_dkg(3, 2)
    assert a[1].group_public_key != b[1].group_public_key


# ---------- атаки ----------
def start(n=4, t=2, session=b"S"):
    parts = {i: DKGParticipant(i, n, t, session) for i in range(1, n + 1)}
    return parts, [p.round1() for p in parts.values()]


def test_bad_proof_of_knowledge_names_culprit():
    parts, r1 = start()
    r1[2] = Round1Package(r1[2].identifier, r1[2].commitments, r1[2].pok_R, (r1[2].pok_mu + 1) % g.L)
    with pytest.raises(DKGError) as e:
        parts[1].round2(r1)
    assert e.value.culprit == 3


def test_rogue_key_attack_is_blocked_by_pok():
    """Атакующий (№4) подбирает φ_0 так, чтобы групповой ключ стал X, не зная его логарифма."""
    parts, r1 = start(n=4, t=2)
    target = g.base_mul(123456789)                       # ключ, который атакующий хочет навязать
    honest = g.IDENTITY
    for p in r1[:3]: honest = g.point_add(honest, p.commitments[0])
    rogue_phi0 = g.point_sub(target, honest)
    # PoK подделать нельзя (нужен лог. rogue_phi0) - пробуем произвольные значения
    k = g.random_scalar()
    forged = Round1Package(4, (rogue_phi0, r1[3].commitments[1]), g.base_mul(k), g.random_scalar())
    with pytest.raises(DKGError) as e:
        parts[1].round2(r1[:3] + [forged])
    assert e.value.culprit == 4 and "PoK" in e.value.reason


def test_pok_is_bound_to_session():
    parts_a, r1_a = start(session=b"session-A")
    parts_b = {i: DKGParticipant(i, 4, 2, b"session-B") for i in range(1, 5)}
    r1_b = [p.round1() for p in parts_b.values()]
    replay = r1_b[:3] + [r1_a[3]]                      # пакет участника 4 из ДРУГОЙ сессии
    with pytest.raises(DKGError) as e:
        parts_b[1].round2(replay)
    assert e.value.culprit == 4


def test_tampered_share_names_sender():
    parts, r1 = start()
    r2 = {i: p.round2(r1) for i, p in parts.items()}
    mine = [pk for s in r2.values() for pk in s if pk.receiver == 1]
    mine[2] = Round2Package(mine[2].sender, 1, (mine[2].share + 1) % g.L)
    with pytest.raises(DKGError) as e:
        parts[1].finalize(mine)
    assert e.value.culprit == mine[2].sender


def test_malformed_round1_packages():
    parts, r1 = start()
    cases = {
        "мало коммитментов": Round1Package(2, r1[1].commitments[:1], r1[1].pok_R, r1[1].pok_mu),
        "нейтральный φ_0": Round1Package(2, (g.IDENTITY,) + r1[1].commitments[1:], r1[1].pok_R, r1[1].pok_mu),
        "мусор вместо точки": Round1Package(2, (bytes(32),) + r1[1].commitments[1:], r1[1].pok_R, r1[1].pok_mu),
        "μ >= L": Round1Package(2, r1[1].commitments, r1[1].pok_R, g.L + 5),
        "id вне диапазона": Round1Package(9, r1[1].commitments, r1[1].pok_R, r1[1].pok_mu),
    }
    for name, bad in cases.items():
        fresh, r1f = start()
        with pytest.raises(DKGError):
            fresh[1].round2([r1f[0], bad, r1f[2], r1f[3]])


def test_missing_or_duplicate_packages_and_order_misuse():
    parts, r1 = start()
    with pytest.raises(DKGError):
        parts[1].round2(r1[:3])
    with pytest.raises(DKGError):
        parts[1].round2(r1[:3] + [r1[2]])
    p = DKGParticipant(1, 4, 2, b"S")
    with pytest.raises(DKGError): p.round2(r1)                       # до round1
    with pytest.raises(DKGError): p.finalize([])                     # до round2
    p.round1()
    with pytest.raises(DKGError): p.round1()                         # повторный round1
    with pytest.raises(DKGError): DKGParticipant(1, 4, 2, b"")      # пустая сессия
    with pytest.raises(DKGError): DKGParticipant(5, 4, 2, b"S")
    with pytest.raises(DKGError): DKGParticipant(1, 4, 5, b"S")


def test_shares_for_other_receiver_or_missing_sender_rejected():
    parts, r1 = start()
    r2 = {i: p.round2(r1) for i, p in parts.items()}
    mine = [pk for s in r2.values() for pk in s if pk.receiver == 1]
    with pytest.raises(DKGError): parts[1].finalize(mine[:3])
    other = [pk for s in r2.values() for pk in s if pk.receiver == 2]
    with pytest.raises(DKGError): parts[1].finalize(other)


def test_pok_is_bound_to_participant_identity():
    """Атакующий №4 копирует коммитменты и PoK участника №3 под своим номером."""
    parts, r1 = start()
    copied = Round1Package(4, r1[2].commitments, r1[2].pok_R, r1[2].pok_mu)
    with pytest.raises(DKGError) as e:
        parts[1].round2(r1[:3] + [copied])
    assert e.value.culprit == 4


def test_noncanonical_share_encoding_rejected():
    parts, r1 = start()
    r2 = {i: p.round2(r1) for i, p in parts.items()}
    mine = [pk for s in r2.values() for pk in s if pk.receiver == 1]
    mine[0] = Round2Package(mine[0].sender, 1, mine[0].share + g.L)       # та же доля + L: по модулю совпадает
    with pytest.raises(DKGError) as e:
        parts[1].finalize(mine)
    assert "неканоническая" in e.value.reason
