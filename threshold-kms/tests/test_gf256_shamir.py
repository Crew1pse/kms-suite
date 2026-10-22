import os
from itertools import combinations
import pytest
from hypothesis import given, settings, strategies as st
from shamir_gf256 import GF256, ShamirSecretSharing

GF256.init_tables()
byte = st.integers(0, 255)


def ref_mul(a, b):  # эталон: умножение "в столбик" по полиному AES 0x11B
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


def test_exp_table_is_a_permutation():
    assert len(set(GF256.EXP[:255])) == 255 and 0 not in GF256.EXP[:255]


@given(byte, byte)
def test_mul_matches_reference(a, b):
    assert GF256.mul(a, b) == ref_mul(a, b)


@given(byte, st.integers(1, 255))
def test_div_inverts_mul(a, b):
    assert GF256.div(GF256.mul(a, b), b) == a


@given(byte, byte, byte)
def test_distributive(a, b, c):
    assert GF256.mul(a, GF256.add(b, c)) == GF256.add(GF256.mul(a, b), GF256.mul(a, c))


def test_div_by_zero():
    with pytest.raises(ZeroDivisionError):
        GF256.div(5, 0)


@settings(deadline=None, max_examples=60)
@given(st.binary(min_size=1, max_size=40), st.integers(2, 6), st.data())
def test_any_k_shares_recover_fewer_do_not(secret, k, data):
    n = data.draw(st.integers(k, 8))
    s = ShamirSecretSharing()
    shares = s.split_bytes(secret, n, k)
    idx = data.draw(st.lists(st.integers(0, n - 1), min_size=k, max_size=n, unique=True))
    assert s.recover_bytes([shares[i] for i in idx]) == secret
    if len(secret) >= 8:   # k-1 долей не должны давать секрет (вероятность совпадения 2^-64)
        assert s.recover_bytes(shares[: k - 1]) != secret


def test_shares_differ_between_runs():
    s = ShamirSecretSharing()
    a, b = s.split_bytes(b"\x01" * 32, 5, 3), s.split_bytes(b"\x01" * 32, 5, 3)
    assert a != b


def test_threshold_one_degenerate():
    s = ShamirSecretSharing()
    sh = s.split_bytes(b"abc", 3, 1)
    assert all(s.recover_bytes([x]) == b"abc" for x in sh)
