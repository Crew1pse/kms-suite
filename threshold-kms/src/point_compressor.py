from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point

CURVE = SECP256k1.curve
P = CURVE.p()
A = CURVE.a()
B = CURVE.b()

class PointCompressor:
    @staticmethod
    def compress(point: Point) -> bytes:
        x_bytes = point.x().to_bytes(32, byteorder='big')
        prefix = b'\x02' if point.y() % 2 == 0 else b'\x03'
        return prefix + x_bytes

    @staticmethod
    def decompress(compressed_bytes: bytes) -> Point:
        if len(compressed_bytes) != 33:
            raise ValueError("Сжатая точка должна быть ровно 33 байта")
            
        prefix = compressed_bytes[0]
        if prefix not in (2, 3):
            raise ValueError("Неверный префикс")
            
        x = int.from_bytes(compressed_bytes[1:], byteorder='big')
        if x >= P:
            raise ValueError("Некорректная координата x (не каноническая)")
        v = (pow(x, 3, P) + A * x + B) % P
        y = pow(v, (P + 1) // 4, P)
        if (y * y) % P != v:   # x не лежит на кривой (assert в ecdsa вырезается при python -O)
            raise ValueError("Точка не лежит на кривой")
        
        is_y_even = (y % 2 == 0)
        is_prefix_even = (prefix == 2)
        
        if is_y_even != is_prefix_even:
            y = P - y
            
        return Point(CURVE, x, y)
