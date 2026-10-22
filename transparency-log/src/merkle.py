"""Merkle tree по RFC 9162 (Certificate Transparency v2) / RFC 6962: доменное разделение листьев и узлов,
доказательства включения и согласованности и их верификаторы. Только hashlib."""
import hashlib

HASH_LEN = 32


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(data: bytes) -> bytes:
    return _h(b"\x00" + data)


def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b"\x01" + left + right)


EMPTY_ROOT = _h(b"")


def _split(n: int) -> int:
    """Наибольшая степень двойки, строго меньшая n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _is_pow2(x: int) -> bool:
    return x > 0 and x & (x - 1) == 0


class MerkleTree:
    """Дерево над списком хэшей листьев. Полные выровненные поддеревья кэшируются (они неизменяемы)."""

    def __init__(self, leaf_hashes=()):
        self.leaves: list[bytes] = list(leaf_hashes)
        self._cache: dict[tuple[int, int], bytes] = {}

    def __len__(self):
        return len(self.leaves)

    def append(self, data: bytes) -> int:
        self.leaves.append(leaf_hash(data))
        return len(self.leaves) - 1

    def _mth(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_ROOT
        if n == 1:
            return self.leaves[lo]
        cacheable = _is_pow2(n) and lo % n == 0
        if cacheable and (lo, hi) in self._cache:
            return self._cache[(lo, hi)]
        k = _split(n)
        r = node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))
        if cacheable:
            self._cache[(lo, hi)] = r
        return r

    def root(self, size: int | None = None) -> bytes:
        size = len(self.leaves) if size is None else size
        if not 0 <= size <= len(self.leaves):
            raise ValueError("size вне диапазона")
        return self._mth(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        size = len(self.leaves) if size is None else size
        if not (0 <= index < size <= len(self.leaves)):
            raise ValueError("index/size вне диапазона")

        def path(m, lo, hi):
            n = hi - lo
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, lo, lo + k) + [self._mth(lo + k, hi)]
            return path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]

        return path(index, 0, size)

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        second = len(self.leaves) if second is None else second
        if not (1 <= first <= second <= len(self.leaves)):
            raise ValueError("нужно 1 <= first <= second <= размер")
        if first == second:
            return []

        def sub(m, lo, hi, b):
            n = hi - lo
            if m == n:
                return [] if b else [self._mth(lo, hi)]
            k = _split(n)
            if m <= k:
                return sub(m, lo, lo + k, b) + [self._mth(lo + k, hi)]
            return sub(m - k, lo + k, hi, False) + [self._mth(lo, lo + k)]

        return sub(first, 0, second, True)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2. leaf - исходные данные записи (не хэш)."""
    if not (0 <= index < size) or any(len(p) != HASH_LEN for p in proof):
        return False
    fn, sn, r = index, size - 1, leaf_hash(leaf)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2: дерево размера `second` является продолжением дерева размера `first`."""
    if not (1 <= first <= second) or any(len(p) != HASH_LEN for p in proof):
        return False
    if first == second:
        return not proof and first_root == second_root
    path = list(proof)
    if _is_pow2(first):
        path.insert(0, first_root)
    if not path:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == first_root and sr == second_root
