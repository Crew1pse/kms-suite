"""Короткоживущие X.509-SVID в стиле SPIFFE: идентичность = URI SAN spiffe://<домен>/<путь>."""
import datetime as dt
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

MAX_TTL = dt.timedelta(hours=1)
_SPIFFE = re.compile(r"^spiffe://([a-z0-9.-]+)((?:/[A-Za-z0-9._-]+)*)$")


class SvidError(Exception): pass


def parse_spiffe_id(s: str) -> tuple[str, str]:
    m = _SPIFFE.match(s)
    if not m or ".." in s.split("/")[3:] or "." in s.split("/")[3:]:
        raise SvidError(f"некорректный SPIFFE ID: {s!r}")
    return m.group(1), m.group(2)


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def key_pem(k) -> bytes:
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def make_csr(key, spiffe_id: str | None = None) -> bytes:
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
    if spiffe_id:   # запрошенный ID - только пожелание; CA его игнорирует и берёт аттестованный
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


def spiffe_id_of(cert: x509.Certificate) -> str:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        raise SvidError("нет SAN")
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise SvidError("SVID должен содержать ровно один URI SAN")
    parse_spiffe_id(uris[0])
    return uris[0]


@dataclass
class CertAuthority:
    trust_domain: str
    key: ec.EllipticCurvePrivateKey = field(default_factory=new_key)
    cert: x509.Certificate = None

    def __post_init__(self):
        if self.cert is None:
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"CA {self.trust_domain} {secrets.token_hex(4)}")])
            now = dt.datetime.now(dt.timezone.utc)
            self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                         .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                         .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=30))
                         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                         .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                         .sign(self.key, hashes.SHA256()))

    def issue(self, csr_pem: bytes, spiffe_id: str, ttl: dt.timedelta = dt.timedelta(minutes=10),
              now: dt.datetime | None = None) -> x509.Certificate:
        td, _ = parse_spiffe_id(spiffe_id)
        if td != self.trust_domain:
            raise SvidError("чужой trust domain")
        if not dt.timedelta(0) < ttl <= MAX_TTL:
            raise SvidError(f"TTL должен быть в (0, {MAX_TTL}]")
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise SvidError("подпись CSR неверна (нет владения ключом)")
        if not isinstance(csr.public_key(), ec.EllipticCurvePublicKey):
            raise SvidError("поддерживается только ECDSA")
        now = now or dt.datetime.now(dt.timezone.utc)
        return (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(self.cert.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(seconds=30)).not_valid_after(now + ttl)
                .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]), critical=True)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self.key, hashes.SHA256()))


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def verify_svid(cert: x509.Certificate, bundle: list[x509.Certificate], trust_domain: str,
                expected_id: str | None = None, now: dt.datetime | None = None) -> str:
    """Возвращает SPIFFE ID, если SVID подписан одним из CA в bundle, действителен и принадлежит домену."""
    now = now or dt.datetime.now(dt.timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise SvidError("SVID просрочен или ещё не действителен")
    ok = False
    for ca in bundle:
        if ca.subject != cert.issuer:
            continue
        if not (ca.not_valid_before_utc <= now <= ca.not_valid_after_utc):
            continue
        try:
            ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
            ok = True
            break
        except InvalidSignature:
            continue
    if not ok:
        raise SvidError("подпись не сходится ни с одним CA из trust bundle")
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        raise SvidError("нет BasicConstraints")
    if bc.ca:
        raise SvidError("листовой SVID не может быть CA")
    sid = spiffe_id_of(cert)
    if parse_spiffe_id(sid)[0] != trust_domain:
        raise SvidError("чужой trust domain")
    if expected_id is not None and not hmac.compare_digest(sid, expected_id):
        raise SvidError(f"ожидался {expected_id}, получен {sid}")
    return sid
