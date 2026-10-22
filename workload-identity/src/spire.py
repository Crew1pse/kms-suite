"""Мини-SPIRE: сервер регистраций + аттестация по одноразовому join-токену + продление по действующему SVID."""
import datetime as dt
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from cryptography import x509

from svid import CertAuthority, SvidError, make_csr, new_key, key_pem, pem, parse_spiffe_id, verify_svid


class AttestationError(Exception): pass


@dataclass
class _Entry:
    spiffe_id: str
    token_hash: bytes
    expires: dt.datetime
    used: bool = False


class SpireServer:
    def __init__(self, trust_domain: str, svid_ttl: dt.timedelta = dt.timedelta(minutes=10)):
        self.trust_domain, self.ttl = trust_domain, svid_ttl
        self.cas = [CertAuthority(trust_domain)]       # [-1] - активный, предыдущие - только для проверки
        self._entries: list[_Entry] = []
        self.issued: list[tuple[str, int]] = []         # журнал (spiffe_id, serial)

    # --- администратор ---
    def create_join_token(self, spiffe_id: str, ttl: dt.timedelta = dt.timedelta(minutes=5), now=None) -> str:
        if parse_spiffe_id(spiffe_id)[0] != self.trust_domain:
            raise SvidError("чужой trust domain")
        tok = secrets.token_urlsafe(32)
        now = now or dt.datetime.now(dt.timezone.utc)
        self._entries.append(_Entry(spiffe_id, hashlib.sha256(tok.encode()).digest(), now + ttl))   # хранится только хэш
        return tok

    # --- аттестация и выдача ---
    def attest(self, join_token: str, csr_pem: bytes, now=None) -> x509.Certificate:
        now = now or dt.datetime.now(dt.timezone.utc)
        h = hashlib.sha256(join_token.encode()).digest()
        match = None
        for e in self._entries:                         # без раннего выхода: постоянное время по записям
            if hmac.compare_digest(e.token_hash, h):
                match = e
        if match is None or match.used or now > match.expires:
            raise AttestationError("токен недействителен, просрочен или уже использован")
        match.used = True                               # одноразовый: сжигаем до выдачи
        return self._issue(csr_pem, match.spiffe_id, now)

    def renew(self, current: x509.Certificate, csr_pem: bytes, now=None) -> x509.Certificate:
        """Продление: предъявляется ещё действующий SVID; идентичность берётся из НЕГО, а не из CSR."""
        now = now or dt.datetime.now(dt.timezone.utc)
        try:
            sid = verify_svid(current, self.bundle(), self.trust_domain, now=now)
        except SvidError as e:
            raise AttestationError(f"текущий SVID не принят: {e}")
        return self._issue(csr_pem, sid, now)

    def _issue(self, csr_pem, sid, now):
        cert = self.cas[-1].issue(csr_pem, sid, self.ttl, now)
        self.issued.append((sid, cert.serial_number))
        return cert

    # --- trust bundle и ротация CA ---
    def bundle(self) -> list[x509.Certificate]:
        return [c.cert for c in self.cas]

    def rotate_ca(self):
        self.cas.append(CertAuthority(self.trust_domain))

    def retire_old_cas(self):
        self.cas = self.cas[-1:]


class Agent:
    """Держит SVID, сам генерирует ключ (приватный ключ никогда не покидает агента), продлевает на половине срока."""

    def __init__(self, server: SpireServer, join_token: str, now=None):
        self.server = server
        self.key = new_key()
        self.cert = server.attest(join_token, make_csr(self.key), now)

    def needs_renewal(self, now) -> bool:
        life = self.cert.not_valid_after_utc - self.cert.not_valid_before_utc
        return now >= self.cert.not_valid_before_utc + life / 2

    def rotate_if_needed(self, now=None) -> bool:
        now = now or dt.datetime.now(dt.timezone.utc)
        if not self.needs_renewal(now):
            return False
        new = new_key()                                  # новый ключ при каждой ротации
        self.cert = self.server.renew(self.cert, make_csr(new), now)
        self.key = new
        return True

    def write_files(self, directory, bundle=None):
        import os
        os.makedirs(directory, exist_ok=True)
        for name, data in (("svid.key", key_pem(self.key)), ("svid.crt", pem(self.cert)),
                           ("bundle.crt", b"".join(pem(c) for c in (bundle or self.server.bundle())))):
            p = os.path.join(directory, name)
            with open(p, "wb") as f:
                f.write(data)
            if name.endswith(".key"):
                os.chmod(p, 0o600)
