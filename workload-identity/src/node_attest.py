"""Аттестация узла по TPM вместо join-токена: сервер выдаёт SVID узлу, только если
 (1) EK узла подписан доверенным производителем и не отозван,
 (2) AK живёт в том же TPM, что и EK (credential activation),
 (3) свежий quote подписан этим AK над nonce + хэшем CSR, PCR соответствуют политике,
 (4) event log при повторном проигрывании даёт те же PCR и содержит только разрешённые измерения."""
import datetime as dt
import hmac
import secrets
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from softtpm import (TpmError, pcr_digest, pub_der, quote_message, replay_log, make_credential, sha)
from spire import AttestationError, SpireServer


@dataclass
class BootPolicy:
    selection: tuple[int, ...]                               # какие PCR обязаны быть в quote (ровно этот набор)
    allowed_events: dict[int, set[bytes]]                    # pcr -> допустимые sha256(измерение)
    golden: set[bytes] = field(default_factory=set)          # допустимые итоговые digest PCR (если пусто - только проверка событий)


@dataclass
class _Session:
    secret: bytes; ak_name: bytes; ak_pub: bytes; ek_hash: str; nonce: bytes; csr_der: bytes; csr_pem: bytes
    expires: dt.datetime; used: bool = False


@dataclass
class Challenge:
    session_id: str; credential: bytes; nonce: bytes


class NodeAttestor:
    def __init__(self, server: SpireServer, vendor_roots: list[x509.Certificate], policy: BootPolicy,
                 ttl: dt.timedelta = dt.timedelta(seconds=60)):
        self.server, self.roots, self.policy, self.ttl = server, vendor_roots, policy, ttl
        self._sessions: dict[str, _Session] = {}
        self.denylist: set[str] = set()

    def node_spiffe_id(self, ek_hash: str) -> str:
        return f"spiffe://{self.server.trust_domain}/node/{ek_hash[:32]}"

    @staticmethod
    def ek_hash(ek_cert: x509.Certificate) -> str:
        return sha(pub_der(ek_cert.public_key())).hex()

    def _check_ek_cert(self, cert: x509.Certificate, now):
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise AttestationError("EK-сертификат вне срока")
        for root in self.roots:
            if root.subject != cert.issuer:
                continue
            try:
                root.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
                return
            except InvalidSignature:
                continue
        raise AttestationError("EK не подписан доверенным производителем TPM")

    def begin(self, ek_cert: x509.Certificate, ak_pub_der: bytes, csr_pem: bytes, now=None) -> Challenge:
        now = now or dt.datetime.now(dt.timezone.utc)
        self._check_ek_cert(ek_cert, now)
        h = self.ek_hash(ek_cert)
        if h in self.denylist:
            raise AttestationError("EK отозван")
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise AttestationError("CSR: подпись неверна")
        ak_name = sha(ak_pub_der)
        sec, nonce, sid = secrets.token_bytes(32), secrets.token_bytes(32), secrets.token_urlsafe(16)
        self._sessions[sid] = _Session(sec, ak_name, ak_pub_der, h, nonce, csr.public_bytes(serialization.Encoding.DER),
                                       csr_pem, now + self.ttl)
        return Challenge(sid, make_credential(ek_cert.public_key(), ak_name, sec), nonce)

    def complete(self, session_id: str, secret: bytes, quoted: bytes, signature: bytes,
                 event_log: list[tuple[int, bytes]], now=None) -> x509.Certificate:
        now = now or dt.datetime.now(dt.timezone.utc)
        s = self._sessions.get(session_id)
        if s is None or s.used:
            raise AttestationError("сессия неизвестна или уже использована")
        s.used = True                                          # одноразовая: сжигаем до проверок
        if now > s.expires:
            raise AttestationError("сессия просрочена")
        if not hmac.compare_digest(secret, s.secret):
            raise AttestationError("credential activation не пройден: AK и EK не в одном TPM")
        # quote
        qualifying = sha(s.nonce + s.csr_der)                  # quote «подписывает» и nonce, и конкретный CSR
        try:
            pcrs = replay_log(event_log)
        except TpmError as e:
            raise AttestationError(str(e))
        digest = pcr_digest(pcrs, self.policy.selection)
        expected = quote_message(self.policy.selection, digest, qualifying)
        if not hmac.compare_digest(expected, quoted):
            raise AttestationError("quote не соответствует nonce/CSR/PCR/политике выбора PCR")
        try:
            ec_pub = serialization.load_der_public_key(s.ak_pub)
            ec_pub.verify(signature, quoted, ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError):
            raise AttestationError("подпись quote недействительна")
        # политика загрузки
        for pcr, data in event_log:
            allowed = self.policy.allowed_events.get(pcr)
            if allowed is not None and sha(data) not in allowed:
                raise AttestationError(f"недопустимое измерение в PCR{pcr}")
            if allowed is None and pcr in self.policy.selection:
                raise AttestationError(f"PCR{pcr} не имеет политики")
        if self.policy.golden and digest not in self.policy.golden:
            raise AttestationError("PCR не совпадают с эталонными")
        return self.server._issue(s.csr_pem, self.node_spiffe_id(s.ek_hash), now)


def attest_node(tpm, attestor: NodeAttestor, csr_pem: bytes, now=None, selection=None):
    """Клиентская сторона (агент на узле): полный обмен. Возвращает (cert, ak_name)."""
    ak_der, ak_name = tpm.create_ak()
    ch = attestor.begin(tpm.ek_cert, ak_der, csr_pem, now)
    secret = tpm.activate_credential(ak_name, ch.credential)
    csr_der = x509.load_pem_x509_csr(csr_pem).public_bytes(serialization.Encoding.DER)
    quoted, sig = tpm.quote(ak_name, sha(ch.nonce + csr_der), selection or attestor.policy.selection)
    return attestor.complete(ch.session_id, secret, quoted, sig, tpm.event_log, now)
