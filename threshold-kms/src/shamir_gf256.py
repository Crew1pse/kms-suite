import os
from ecdsa import SECP256k1

Q = SECP256k1.generator.order()

class GF256:
    EXP = [0] * 512
    LOG = [0] * 256
    _initialized = False

    @classmethod
    def init_tables(cls):
        if cls._initialized: return
        x = 1
        for i in range(255):
            cls.EXP[i] = x
            cls.LOG[x] = i
            # умножение на 3 (образующий для 0x11B; двойка имеет порядок всего 51)
            x = (x << 1) ^ x
            if x & 0x100:
                x ^= 0x11B
        for i in range(255, 512):
            cls.EXP[i] = cls.EXP[i - 255]
        cls._initialized = True

    @staticmethod
    def add(a: int, b: int) -> int: return a ^ b
    @staticmethod
    def sub(a: int, b: int) -> int: return a ^ b
    @staticmethod
    def mul(a: int, b: int) -> int:
        if a == 0 or b == 0: return 0
        return GF256.EXP[GF256.LOG[a] + GF256.LOG[b]]
    @staticmethod
    def div(a: int, b: int) -> int:
        if b == 0: raise ZeroDivisionError()
        if a == 0: return 0
        return GF256.EXP[(GF256.LOG[a] - GF256.LOG[b] + 255) % 255]

class ShamirSecretSharing:
    def __init__(self):
        GF256.init_tables()

    def split_byte(self, secret: int, n: int, k: int) -> list[tuple[int, int]]:
        coeffs = [secret] + [os.urandom(1)[0] for _ in range(k - 1)]
        while k > 1 and coeffs[-1] == 0:  # старший коэффициент != 0, иначе степень < k-1
            coeffs[-1] = os.urandom(1)[0]
        shares = []
        for x in range(1, n + 1):
            y = 0
            x_pow = 1
            for c in coeffs:
                y = GF256.add(y, GF256.mul(c, x_pow))
                x_pow = GF256.mul(x_pow, x)
            shares.append((x, y))
        return shares

    def recover_byte(self, shares: list[tuple[int, int]]) -> int:
        secret = 0
        for i, (xi, yi) in enumerate(shares):
            num = 1
            den = 1
            for j, (xj, yj) in enumerate(shares):
                if i == j: continue
                num = GF256.mul(num, xj)
                den = GF256.mul(den, GF256.sub(xi, xj))
            lagrange_basis = GF256.div(num, den)
            term = GF256.mul(yi, lagrange_basis)
            secret = GF256.add(secret, term)
        return secret

    def split_bytes(self, secret: bytes, n: int, k: int) -> list[tuple[int, bytes]]:
        share_y_arrays = [bytearray() for _ in range(n)]
        for byte in secret:
            byte_shares = self.split_byte(byte, n, k)
            for i, (x, y) in enumerate(byte_shares):
                share_y_arrays[i].append(y)
        return [(i + 1, bytes(share_y_arrays[i])) for i in range(n)]

    def recover_bytes(self, shares: list[tuple[int, bytes]]) -> bytes:
        if not shares: return b""
        secret_len = len(shares[0][1])
        recovered_secret = bytearray()
        for byte_idx in range(secret_len):
            byte_quorum = [(x, y_bytes[byte_idx]) for x, y_bytes in shares]
            recovered_secret.append(self.recover_byte(byte_quorum))
        return bytes(recovered_secret)

def recover_secret_mod_q(shares: list[tuple[int, int]], q: int) -> int:
    secret = 0
    for i, (xi, yi) in enumerate(shares):
        num = 1
        den = 1
        for j, (xj, yj) in enumerate(shares):
            if i == j: continue
            num = (num * (-xj)) % q
            den = (den * (xi - xj)) % q
        inv_den = pow(den, -1, q)
        lagrange_basis = (num * inv_den) % q
        term = (yi * lagrange_basis) % q
        secret = (secret + term) % q
    return secret
