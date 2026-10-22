import os
import hmac
from ecdsa import SECP256k1
from point_compressor import PointCompressor

G = SECP256k1.generator
Q = G.order()

class FeldmanVSS:
    def __init__(self, threshold: int, total_nodes: int):
        self.k = threshold
        self.n = total_nodes

    def generate_shares_and_commitments(self, secret: int) -> tuple[list[tuple[int, int]], list[str]]:
        if secret >= Q or secret <= 0:
            raise ValueError("Секрет вне диапазона")

        coeffs = [secret]
        for _ in range(self.k - 1):
            while True:
                candidate = int.from_bytes(os.urandom(32), 'big')
                if 0 < candidate < Q:
                    coeffs.append(candidate)
                    break

        commitments = [c * G for c in coeffs]
        compressed_commitments = [PointCompressor.compress(c).hex() for c in commitments]

        shares = []
        for x in range(1, self.n + 1):
            y = 0
            x_pow = 1
            for c in coeffs:
                y = (y + c * x_pow) % Q
                x_pow = (x_pow * x) % Q
            shares.append((x, y))

        return shares, compressed_commitments

    @staticmethod
    def verify_share(x: int, y: int, compressed_commitments: list[str]) -> bool:
        # x=0 раскрывал бы секрет, x>=Q алиасится на малые x, y вне диапазона бессмысленен
        if not (0 < x < Q and 0 < y < Q) or not compressed_commitments:
            return False
        try:
            commitments = [PointCompressor.decompress(bytes.fromhex(c)) for c in compressed_commitments]
            lhs = y * G

            rhs = commitments[0]
            x_pow = x
            for i in range(1, len(commitments)):
                rhs = rhs + x_pow * commitments[i]
                x_pow = (x_pow * x) % Q

            return hmac.compare_digest(lhs.to_bytes('uncompressed'), rhs.to_bytes('uncompressed'))
        except Exception:
            return False
