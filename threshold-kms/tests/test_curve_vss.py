import os
from itertools import combinations
import pytest
from hypothesis import given, settings, strategies as st
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization as ser
from ecdsa import SECP256k1
from feldman_vss import FeldmanVSS, Q, G
from point_compressor import PointCompressor, P
from shamir_gf256 import recover_secret_mod_q

scalar = st.integers(1, Q - 1)


def lib_compressed(c: int) -> bytes:  # эталон: библиотека cryptography
    pub = ec.derive_private_key(c, ec.SECP256K1()).public_key()
    return pub.public_bytes(ser.Encoding.X962, ser.PublicFormat.CompressedPoint)


@settings(deadline=None, max_examples=40)
@given(scalar)
def test_compress_matches_cryptography(c):
    assert PointCompressor.compress(c * G) == lib_compressed(c)


@settings(deadline=None, max_examples=40)
@given(scalar)
def test_decompress_roundtrip(c):
    pt = c * G
    back = PointCompressor.decompress(PointCompressor.compress(pt))
    assert (back.x(), back.y()) == (pt.x(), pt.y())


@given(st.integers(0, P - 1), st.sampled_from([2, 3]))
def test_decompress_rejects_or_returns_valid_point(x, prefix):
    """Для любого x либо ValueError, либо точка на кривой. Любое другое исключение - баг."""
    raw = bytes([prefix]) + x.to_bytes(32, "big")
    try:
        pt = PointCompressor.decompress(raw)
    except ValueError:
        return
    assert (pt.y() ** 2 - pt.x() ** 3 - 7) % P == 0


@pytest.mark.parametrize("raw", [b"", b"\x02", b"\x04" + b"\x00" * 32, b"\x02" + b"\xff" * 32, b"\x05" + b"\x00" * 32])
def test_decompress_malformed_raises_valueerror(raw):
    with pytest.raises(ValueError):
        PointCompressor.decompress(raw)


def _small_x_on_curve():
    for x in range(1, 5000):
        if pow((x ** 3 + 7) % P, (P - 1) // 2, P) == 1:   # квадратичный вычет => точка есть
            return x
    raise RuntimeError


def test_decompress_rejects_noncanonical_x():
    """x и x+p кодируют одну точку: принимать оба нельзя (малleабельность кодирования)."""
    x = _small_x_on_curve()
    assert x + P < 2 ** 256
    ok = bytes([2]) + x.to_bytes(32, "big")
    PointCompressor.decompress(ok)  # каноническая форма принимается
    with pytest.raises(ValueError):
        PointCompressor.decompress(bytes([2]) + (x + P).to_bytes(32, "big"))


@settings(deadline=None, max_examples=15)
@given(scalar, st.integers(2, 5), st.data())
def test_vss_end_to_end(secret, k, data):
    n = data.draw(st.integers(k, 7))
    shares, comm = FeldmanVSS(k, n).generate_shares_and_commitments(secret)
    assert len(comm) == k
    assert comm[0] == lib_compressed(secret).hex()
    assert all(FeldmanVSS.verify_share(x, y, comm) for x, y in shares)
    idx = data.draw(st.lists(st.integers(0, n - 1), min_size=k, max_size=n, unique=True))
    assert recover_secret_mod_q([shares[i] for i in idx], Q) == secret


@settings(deadline=None, max_examples=15)
@given(scalar, st.integers(1, Q - 1))
def test_verify_rejects_any_tampering(secret, delta):
    shares, comm = FeldmanVSS(3, 5).generate_shares_and_commitments(secret)
    x, y = shares[0]
    assert not FeldmanVSS.verify_share(x, (y + delta) % Q or 1, comm) or (y + delta) % Q == y
    assert not FeldmanVSS.verify_share(x + 1, y, comm)          # доля от другого x


@pytest.mark.parametrize("x,y", [(0, 5), (-1, 5), (Q, 5), (Q + 1, 5), (1, 0), (1, Q), (1, -3)])
def test_verify_rejects_out_of_range(x, y):
    _, comm = FeldmanVSS(3, 5).generate_shares_and_commitments(12345)
    assert FeldmanVSS.verify_share(x, y, comm) is False


@given(st.lists(st.text(max_size=80), max_size=5))
def test_verify_never_raises_on_garbage(garbage):
    assert FeldmanVSS.verify_share(1, 2, garbage) is False


def test_generate_rejects_bad_secret():
    for bad in (0, -1, Q, Q + 5):
        with pytest.raises(ValueError):
            FeldmanVSS(3, 5).generate_shares_and_commitments(bad)


def test_recover_duplicate_x_fails_loudly():
    with pytest.raises(ValueError):   # pow(0, -1, q)
        recover_secret_mod_q([(1, 5), (1, 7), (2, 9)], Q)


def test_coefficients_are_not_zero_and_unique_per_run():
    s1 = FeldmanVSS(3, 5).generate_shares_and_commitments(7)[1]
    s2 = FeldmanVSS(3, 5).generate_shares_and_commitments(7)[1]
    assert s1[0] == s2[0] and s1[1:] != s2[1:]


def test_verify_rejects_share_at_zero_that_equals_secret():
    """x=0 раскрывает секрет: доля (0, secret) формально 'валидна' для полинома, но принимать её нельзя."""
    secret = 424242
    _, comm = FeldmanVSS(3, 5).generate_shares_and_commitments(secret)
    assert FeldmanVSS.verify_share(0, secret, comm) is False
