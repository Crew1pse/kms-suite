import hashlib
import pytest
from hypothesis import given, settings, strategies as st
from merkle import MerkleTree, verify_inclusion, verify_consistency, leaf_hash, node_hash, EMPTY_ROOT

# Эталонные данные Certificate Transparency (google/certificate-transparency, Trillian)
CT_LEAVES = [bytes.fromhex(x) for x in
             ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]]
CT_ROOTS = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]


def tree(n):
    t = MerkleTree()
    for i in range(n):
        t.append(f"entry-{i}".encode())
    return t


def naive_mth(items):  # независимая реализация определения из RFC (без кэша и без индексов)
    if not items:
        return hashlib.sha256(b"").digest()
    if len(items) == 1:
        return hashlib.sha256(b"\x00" + items[0]).digest()
    k = 1
    while k * 2 < len(items):
        k *= 2
    return hashlib.sha256(b"\x01" + naive_mth(items[:k]) + naive_mth(items[k:])).digest()


def test_ct_reference_roots():
    t = MerkleTree()
    assert t.root().hex() == CT_ROOTS[0]
    for i, leaf in enumerate(CT_LEAVES, 1):
        t.append(leaf)
        assert t.root().hex() == CT_ROOTS[i], f"корень для {i} листьев"


def test_empty_and_single():
    assert MerkleTree().root() == EMPTY_ROOT
    assert tree(1).root() == leaf_hash(b"entry-0")


def test_leaf_and_node_domain_separation():
    d = b"x" * 64
    assert leaf_hash(d) != node_hash(d[:32], d[32:])  # второй прообраз "лист как узел" невозможен


@pytest.mark.parametrize("n", range(1, 40))
def test_root_matches_naive(n):
    assert tree(n).root() == naive_mth([f"entry-{i}".encode() for i in range(n)])


@pytest.mark.parametrize("n", range(1, 34))
def test_all_inclusion_proofs_verify(n):
    t = tree(n); root = t.root()
    for i in range(n):
        assert verify_inclusion(f"entry-{i}".encode(), i, n, t.inclusion_proof(i), root)


@pytest.mark.parametrize("n", range(1, 34))
def test_inclusion_rejects_wrong_data_index_size_proof(n):
    t = tree(n); root = t.root()
    for i in range(n):
        p = t.inclusion_proof(i)
        assert not verify_inclusion(b"forged", i, n, p, root)
        assert not verify_inclusion(f"entry-{i}".encode(), (i + 1) % n if n > 1 else 1, n, p, root)
        # Размер дерева корень НЕ фиксирует (правый брат - непрозрачный хэш), поэтому пара (size, root)
        # берётся только из подписанного корня STH - это проверяет test_log.py. Здесь size+1 не проверяем.
        if p:
            bad = list(p); bad[0] = bytes(32)
            assert not verify_inclusion(f"entry-{i}".encode(), i, n, bad, root)
            assert not verify_inclusion(f"entry-{i}".encode(), i, n, p[:-1], root)
            assert not verify_inclusion(f"entry-{i}".encode(), i, n, p + [bytes(32)], root)


def test_inclusion_at_historic_size():
    t = tree(20)
    for size in (1, 5, 8, 13, 20):
        for i in range(size):
            assert verify_inclusion(f"entry-{i}".encode(), i, size, t.inclusion_proof(i, size), t.root(size))


@pytest.mark.parametrize("n", range(1, 26))
def test_all_consistency_proofs_verify(n):
    t = tree(n); second_root = t.root()
    for m in range(1, n + 1):
        assert verify_consistency(m, n, t.root(m), second_root, t.consistency_proof(m, n)), (m, n)


@pytest.mark.parametrize("n", range(2, 20))
def test_consistency_rejects_forgery(n):
    t = tree(n); r2 = t.root()
    for m in range(1, n):
        p = t.consistency_proof(m, n); r1 = t.root(m)
        other = MerkleTree()
        for i in range(n):
            other.append(b"EVIL" if i == 0 else f"entry-{i}".encode())   # переписанная первая запись
        assert not verify_consistency(m, n, other.root(m), r2, p)           # старый корень подменён
        assert not verify_consistency(m, n, r1, other.root(n), p)           # новый корень подменён
        assert not verify_consistency(m, n, r1, r2, p[:-1] if p else [bytes(32)])
        assert not verify_consistency(m, n, r1, r2, p + [bytes(32)])
        assert not verify_consistency(m, n, r1, bytes(32), p)


def test_consistency_equal_sizes_and_bounds():
    t = tree(7)
    assert verify_consistency(7, 7, t.root(), t.root(), [])
    assert not verify_consistency(7, 7, t.root(), bytes(32), [])
    assert not verify_consistency(0, 7, EMPTY_ROOT, t.root(), [])
    assert not verify_consistency(8, 7, t.root(), t.root(), [])
    with pytest.raises(ValueError):
        t.consistency_proof(0, 7)
    with pytest.raises(ValueError):
        t.inclusion_proof(7)


@settings(deadline=None, max_examples=40)
@given(st.lists(st.binary(max_size=40), min_size=1, max_size=60), st.data())
def test_random_logs_proofs_and_prefix_roots(entries, data):
    t = MerkleTree()
    for e in entries:
        t.append(e)
    n = len(entries)
    assert t.root() == naive_mth(entries)
    i = data.draw(st.integers(0, n - 1)); m = data.draw(st.integers(1, n))
    assert verify_inclusion(entries[i], i, n, t.inclusion_proof(i), t.root())
    assert verify_consistency(m, n, t.root(m), t.root(), t.consistency_proof(m, n))
    assert t.root(m) == naive_mth(entries[:m])      # корень префикса не зависит от хвоста
