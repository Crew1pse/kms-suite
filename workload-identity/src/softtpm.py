"""Программная модель TPM 2.0 - только то, что нужно для аттестации узла:
 EK (ключ, зашитый производителем, + сертификат производителя), PCR с операцией extend и event log,
 AK (ключ аттестации, создаётся внутри TPM), quote (подпись AK над PCR и nonce), credential activation
 (секрет, зашифрованный на EK и привязанный к имени AK: расшифровать может только тот TPM, где живут И EK, И этот AK).
Это МОДЕЛЬ для тестов протокола, а не TPM: нет защиты ключей аппаратурой, секрет лежит в памяти Python."""
import datetime as dt
import hashlib
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID

NUM_PCR = 8
QUOTE_MAGIC = b"SOFTTPM-QUOTE-v1"


class TpmError(Exception): pass


def sha(b: bytes) -> bytes: return hashlib.sha256(b).digest()


def pub_der(k) -> bytes:
    return k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def extend(pcr: bytes, data: bytes) -> bytes:
    return sha(pcr + sha(data))


def replay_log(log: list[tuple[int, bytes]]) -> list[bytes]:
    pcrs = [bytes(32)] * NUM_PCR
    for idx, data in log:
        if not 0 <= idx < NUM_PCR:
            raise TpmError("PCR вне диапазона")
        pcrs[idx] = extend(pcrs[idx], data)
    return pcrs


def pcr_digest(pcrs: list[bytes], selection: tuple[int, ...]) -> bytes:
    return sha(b"".join(pcrs[i] for i in selection))


def quote_message(selection: tuple[int, ...], digest: bytes, qualifying: bytes) -> bytes:
    return QUOTE_MAGIC + struct.pack(">B", len(selection)) + bytes(selection) + digest + sha(qualifying)


class Manufacturer:
    """Производитель TPM: подписывает сертификаты EK. Его корень - то, чему доверяет сервер."""

    def __init__(self, name="Soft TPM Vendor"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(self.key.public_key())
                     .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
                     .not_valid_after(now + dt.timedelta(days=3650))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), True).sign(self.key, hashes.SHA256()))

    def issue_ek_cert(self, ek_pub) -> x509.Certificate:
        now = dt.datetime.now(dt.timezone.utc)
        return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TPM EK")]))
                .issuer_name(self.cert.subject).public_key(ek_pub).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(self.key, hashes.SHA256()))


def make_credential(ek_pub: ec.EllipticCurvePublicKey, ak_name: bytes, secret: bytes) -> bytes:
    """Сторона сервера: шифрует секрет на EK и привязывает к имени AK (ECDH-ES + AES-GCM, AAD = имя AK)."""
    eph = ec.generate_private_key(ec.SECP256R1())
    key = HKDF(hashes.SHA256(), 32, None, b"softtpm-cred" + ak_name).derive(eph.exchange(ec.ECDH(), ek_pub))
    nonce = os.urandom(12)
    return pub_der(eph.public_key()) + nonce + AESGCM(key).encrypt(nonce, secret, ak_name)


class SoftTPM:
    def __init__(self, vendor: Manufacturer):
        self._ek = ec.generate_private_key(ec.SECP256R1())
        self.ek_cert = vendor.issue_ek_cert(self._ek.public_key())
        self.pcrs = [bytes(32)] * NUM_PCR
        self.event_log: list[tuple[int, bytes]] = []
        self._aks: dict[bytes, ec.EllipticCurvePrivateKey] = {}

    def measure(self, pcr: int, data: bytes):
        """Измерение при загрузке (в реальности делает прошивка/загрузчик; PCR нельзя «записать», только расширить)."""
        self.pcrs[pcr] = extend(self.pcrs[pcr], data)
        self.event_log.append((pcr, data))

    def create_ak(self) -> tuple[bytes, bytes]:
        k = ec.generate_private_key(ec.SECP256R1())
        der = pub_der(k.public_key()); name = sha(der)
        self._aks[name] = k
        return der, name

    def activate_credential(self, ak_name: bytes, blob: bytes) -> bytes:
        if ak_name not in self._aks:
            raise TpmError("AK не загружен в этот TPM")
        try:
            eph = serialization.load_der_public_key(blob[:91])
            nonce, ct = blob[91:103], blob[103:]
            key = HKDF(hashes.SHA256(), 32, None, b"softtpm-cred" + ak_name).derive(self._ek.exchange(ec.ECDH(), eph))
            return AESGCM(key).decrypt(nonce, ct, ak_name)
        except Exception:
            raise TpmError("не удалось активировать credential (не тот EK или не то имя AK)")

    def quote(self, ak_name: bytes, qualifying: bytes, selection: tuple[int, ...]) -> tuple[bytes, bytes]:
        ak = self._aks.get(ak_name)
        if ak is None:
            raise TpmError("AK не загружен в этот TPM")
        msg = quote_message(tuple(selection), pcr_digest(self.pcrs, tuple(selection)), qualifying)
        return msg, ak.sign(msg, ec.ECDSA(hashes.SHA256()))
