import os, random
from itertools import combinations
import pytest
from hypothesis import given, settings, strategies as st
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import ed25519_group as g
import frost
from frost import (Signer, Commitment, SignatureShare, FrostError, NonceReuseError, InvalidShare,
                   trusted_dealer_keygen, aggregate, verify, verify_share, binding_factors)
from helpers import sign_with


def independent_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg); return True
    except (InvalidSignature, ValueError):
        return False


@pytest.fixture(scope="module")
def keys35():
    return trusted_dealer_keygen(5, 3)


@pytest.mark.parametrize("t,n", [(1, 1), (1, 3), (2, 2), (2, 3), (3, 5)])
def test_every_quorum_signs_and_standard_ed25519_verifier_accepts(t, n):
    pkg, shares = trusted_dealer_keygen(n, t)
    msg = b"pay 100 to alice"
    for size in range(t, n + 1):
        for ids in combinations(range(1, n + 1), size):
            sig = sign_with(pkg, shares, ids, msg)
            assert independent_verify(pkg.group_public_key, msg, sig), ids      # обычный Ed25519!
            assert verify(pkg.group_public_key, msg, sig)


@settings(deadline=None, max_examples=25)
@given(st.binary(max_size=300))
def test_arbitrary_messages(keys35, msg):
    pkg, shares = keys35
    ids = random.sample(range(1, 6), 3)
    assert independent_verify(pkg.group_public_key, msg, sign_with(pkg, shares, ids, msg))


def test_signatures_are_randomized_and_bound_to_message_and_key(keys35):
    pkg, shares = keys35
    a, b = sign_with(pkg, shares, [1, 2, 3], b"m"), sign_with(pkg, shares, [1, 2, 3], b"m")
    assert a != b                                     # nonce свежие
    assert not independent_verify(pkg.group_public_key, b"other", a)
    other, _ = trusted_dealer_keygen(5, 3)
    assert not independent_verify(other.group_public_key, b"m", a)


def test_below_threshold_cannot_sign(keys35):
    pkg, shares = keys35
    signers = [Signer(shares[i]) for i in (1, 2)]
    coms = [s.commit() for s in signers]
    for s in signers:
        with pytest.raises(FrostError):
            s.sign(b"m", coms)
    with pytest.raises(FrostError):
        aggregate(pkg, b"m", coms, [SignatureShare(c.identifier, 1) for c in coms])


def test_two_shares_of_a_3of5_key_reveal_nothing_useful(keys35):
    """t-1 долей интерполируются в НЕверный ключ (информационно-теоретическая защита Шамира)."""
    pkg, shares = keys35
    ids = [1, 2]
    wrong = sum(g.lagrange_at_zero(ids, i) * shares[i].secret_share for i in ids) % g.L
    assert g.base_mul(wrong) != pkg.group_public_key


def test_dealer_key_matches_shamir_and_secret_parameter():
    s = g.random_scalar()
    pkg, shares = trusted_dealer_keygen(5, 3, secret=s)
    assert pkg.group_public_key == g.base_mul(s)
    ids = [2, 4, 5]
    assert sum(g.lagrange_at_zero(ids, i) * shares[i].secret_share for i in ids) % g.L == s


# ---------- повторное использование nonce ----------
def test_nonce_reuse_is_refused(keys35):
    pkg, shares = keys35
    s1, s2, s3 = (Signer(shares[i]) for i in (1, 2, 3))
    coms = [s.commit() for s in (s1, s2, s3)]
    s1.sign(b"first", coms)
    with pytest.raises(NonceReuseError):
        s1.sign(b"second message, same commitments", coms)    # иначе из двух долей подписи вычисляется ключ
    with pytest.raises(NonceReuseError):
        s1.sign(b"first", coms)


def test_each_commit_has_fresh_nonces_and_foreign_commitment_refused(keys35):
    pkg, shares = keys35
    s = Signer(shares[1])
    c1, c2 = s.commit(), s.commit()
    assert (c1.hiding, c1.binding) != (c2.hiding, c2.binding)
    others = [Signer(shares[i]).commit() for i in (2, 3)]
    forged = Commitment(1, g.base_mul(5), g.base_mul(6))
    with pytest.raises(NonceReuseError):
        s.sign(b"m", [forged] + others)


# ---------- злонамеренный координатор ----------
def round1(shares, ids):
    signers = {i: Signer(shares[i]) for i in ids}
    return signers, [s.commit() for s in signers.values()]


def test_signer_rejects_malformed_commitment_lists(keys35):
    pkg, shares = keys35
    signers, coms = round1(shares, [1, 2, 3])
    s = signers[1]
    with pytest.raises(FrostError):
        s.sign(b"m", coms + [coms[1]])                                          # дубликат
    with pytest.raises(FrostError):
        s.sign(b"m", [c for c in coms if c.identifier != 1])                    # меня нет
    with pytest.raises(FrostError):
        s.sign(b"m", coms + [Commitment(0, g.base_mul(3), g.base_mul(4))])      # id=0
    with pytest.raises(FrostError):
        s.sign(b"m", coms + [Commitment(70000, g.base_mul(3), g.base_mul(4))])  # id вне диапазона
    with pytest.raises(FrostError):
        s.sign(b"m", coms + [Commitment(4, g.IDENTITY, g.base_mul(4))])         # нейтральный элемент
    with pytest.raises(FrostError):
        s.sign(b"m", coms + [Commitment(4, bytes(32), g.base_mul(4))])          # малый порядок
    assert s._pending, "nonce не должны расходоваться при отказе"


def test_coordinator_substituting_signers_own_commitment_is_caught(keys35):
    pkg, shares = keys35
    signers, coms = round1(shares, [1, 2, 3])
    tampered = [Commitment(1, g.base_mul(77), coms[0].binding)] + coms[1:]
    with pytest.raises(NonceReuseError):
        signers[1].sign(b"m", tampered)


def test_invalid_share_is_attributed_to_culprit(keys35):
    pkg, shares = keys35
    signers, coms = round1(shares, [1, 2, 3])
    sh = [s.sign(b"m", coms) for s in signers.values()]
    sh[1] = SignatureShare(sh[1].identifier, (sh[1].z + 1) % g.L)
    with pytest.raises(InvalidShare) as e:
        aggregate(pkg, b"m", coms, sh)
    assert e.value.identifier == 2


def test_signers_given_different_messages_are_detected(keys35):
    pkg, shares = keys35
    signers, coms = round1(shares, [1, 2, 3])
    sh = [signers[1].sign(b"A", coms), signers[2].sign(b"A", coms), signers[3].sign(b"B", coms)]
    with pytest.raises(InvalidShare) as e:
        aggregate(pkg, b"A", coms, sh)
    assert e.value.identifier == 3


def test_aggregate_rejects_share_set_mismatch(keys35):
    pkg, shares = keys35
    signers, coms = round1(shares, [1, 2, 3])
    sh = [s.sign(b"m", coms) for s in signers.values()]
    with pytest.raises(FrostError):
        aggregate(pkg, b"m", coms, sh[:2])
    with pytest.raises(FrostError):
        aggregate(pkg, b"m", coms, sh[:2] + [SignatureShare(4, 1)])


def test_verify_share_true_for_honest_false_for_random(keys35):
    pkg, shares = keys35
    signers, coms = round1(shares, [1, 3, 5])
    for s in signers.values():
        sh = s.sign(b"m", coms)
        assert verify_share(pkg, b"m", coms, sh)
        assert not verify_share(pkg, b"m", coms, SignatureShare(sh.identifier, g.random_scalar()))
        assert not verify_share(pkg, b"other", coms, sh)
    assert not verify_share(pkg, b"m", coms, SignatureShare(9, 1))


# ---------- коэффициенты связывания ----------
def test_binding_factors_depend_on_message_and_every_commitment(keys35):
    pkg, shares = keys35
    _, coms = round1(shares, [1, 2, 3])
    base = binding_factors(pkg.group_public_key, b"m", coms)
    assert len(set(base.values())) == 3                                   # разные для разных участников
    assert binding_factors(pkg.group_public_key, b"m2", coms) != base
    for k in range(3):
        for field in ("hiding", "binding"):
            bad = list(coms); old = bad[k]
            bad[k] = Commitment(old.identifier, g.base_mul(999) if field == "hiding" else old.hiding,
                                g.base_mul(998) if field == "binding" else old.binding)
            nb = binding_factors(pkg.group_public_key, b"m", bad)
            assert all(nb[i] != base[i] for i in base), (k, field)         # менялись ВСЕ ρ, не только свой


# ---------- верификатор ----------
def test_verifier_rejects_malformed_signatures(keys35):
    pkg, shares = keys35
    sig = sign_with(pkg, shares, [1, 2, 3], b"m")
    pk = pkg.group_public_key
    z = int.from_bytes(sig[32:], "little")
    assert verify(pk, b"m", sig)
    assert not verify(pk, b"m", sig[:-1])
    assert not verify(pk, b"m", sig + b"\x00")
    assert not verify(pk, b"m", sig[:32] + (z + g.L).to_bytes(32, "little"))        # S+L: неканоническая
    assert not verify(pk, b"m", g.IDENTITY + sig[32:])
    assert not verify(pk, b"m", bytes(64))
    assert not verify(pk, b"m", bytes([sig[0] ^ 1]) + sig[1:])
    assert not independent_verify(pk, b"m", sig[:32] + (z + g.L).to_bytes(32, "little"))   # и эталон отвергает
