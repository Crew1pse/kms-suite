import hashlib
import pytest
from hypothesis import given, strategies as st
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization as ser
import ed25519_group as g
from ed25519_group import L, GroupError

scalar = st.integers(1, L - 1)


def test_base_mul_matches_independent_public_key_derivation():
    for _ in range(20):
        sk = Ed25519PrivateKey.generate()
        seed = sk.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        h = bytearray(hashlib.sha512(seed).digest()[:32])
        h[0] &= 248; h[31] &= 127; h[31] |= 64
        a = int.from_bytes(h, "little") % L          # RFC 8032: скаляр после зажима
        pub = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        assert g.base_mul(a) == pub


@given(scalar, scalar)
def test_group_laws(a, b):
    A, B = g.base_mul(a), g.base_mul(b)
    assert g.point_add(A, B) == g.base_mul(a + b)
    assert g.point_mul(a, B) == g.base_mul(a * b)
    assert g.point_sub(g.point_add(A, B), B) == A
    assert g.point_add(A, g.point_neg(A)) == g.IDENTITY
    assert g.point_add(g.IDENTITY, A) == A and g.point_mul(0, A) == g.IDENTITY
    assert g.base_mul(L) == g.IDENTITY


@pytest.mark.parametrize("bad", [
    g.IDENTITY,                                                  # нейтральный
    bytes.fromhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),   # порядок 2
    bytes(32),                                                   # y=0, малый порядок (4)
    b"\x02" * 31, b"", b"\x02" * 33,                             # длина
    bytes.fromhex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),   # не на кривой / неканоническая
])
def test_validate_point_rejects(bad):
    with pytest.raises(GroupError):
        g.validate_point(bad)


def test_validate_point_accepts_good_and_identity_when_allowed():
    P = g.base_mul(12345)
    assert g.validate_point(P) == P
    assert g.validate_point(g.IDENTITY, allow_identity=True) == g.IDENTITY


def test_scalar_encoding_is_strict():
    assert g.de_scalar(g.ser_scalar(7)) == 7
    for bad in (L.to_bytes(32, "little"), (L + 5).to_bytes(32, "little"), b"\x00" * 31, b"\x00" * 33):
        with pytest.raises(GroupError):
            g.de_scalar(bad)


def test_lagrange_recovers_secret():
    import random
    t, secret = 4, g.random_scalar()
    coeffs = [secret] + [g.random_scalar() for _ in range(t - 1)]
    f = lambda x: sum(c * pow(x, k, L) for k, c in enumerate(coeffs)) % L
    ids = random.sample(range(1, 20), t)
    assert sum(g.lagrange_at_zero(ids, i) * f(i) for i in ids) % L == secret
    with pytest.raises(GroupError):
        g.lagrange_at_zero([1, 2, 2], 1)
    with pytest.raises(GroupError):
        g.lagrange_at_zero([1, 2], 3)
