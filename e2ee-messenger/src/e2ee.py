"""X3DH + Double Ratchet (спецификации Signal) на X25519 / HKDF-SHA256 / HMAC-SHA256 / AES-256-GCM.

Свойства: сквозное шифрование, forward secrecy (ключи сообщений одноразовые и удаляются),
post-compromise security (DH-храповик лечит сессию после утечки состояния), отказ от повторов и подмен.
Состояние меняется АТОМАРНО: только после успешной аутентификации сообщения."""
import copy
import hashlib
import hmac
import os
import struct
from collections import OrderedDict
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_SKIP = 1000          # сколько сообщений можно пропустить в одной цепочке
MAX_STORED_SKIPPED = 2000


class E2EEError(Exception): pass
class DecryptionError(E2EEError): pass
class SkipLimitExceeded(DecryptionError): pass
class IdentityChanged(E2EEError): pass


# ---------- примитивы ----------
def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _raw_pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_priv(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _dh(priv_raw: bytes, pub_raw: bytes) -> bytes:
    try:
        return X25519PrivateKey.from_private_bytes(priv_raw).exchange(X25519PublicKey.from_public_bytes(pub_raw))
    except ValueError as e:      # малый порядок / неверная длина
        raise E2EEError(f"недопустимый открытый ключ: {e}")


def _gen() -> tuple[bytes, bytes]:
    p = X25519PrivateKey.generate()
    return _raw_priv(p), _raw_pub(p)


# ---------- идентичность и X3DH ----------
@dataclass(frozen=True)
class IdentityPublic:
    dh: bytes      # X25519 для X3DH
    sig: bytes     # Ed25519 для подписи prekey

    def fingerprint(self) -> bytes:
        return hashlib.sha256(b"IDENTITY-v1" + self.dh + self.sig).digest()


class IdentityKeyPair:
    def __init__(self):
        self.dh_priv, dh_pub = _gen()
        self._sig = Ed25519PrivateKey.generate()
        self.public = IdentityPublic(dh_pub, self._sig.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def sign(self, msg: bytes) -> bytes:
        return self._sig.sign(msg)


def safety_number(a: IdentityPublic, b: IdentityPublic) -> str:
    """Для сверки по другому каналу: симметрична, меняется при смене любого ключа."""
    d = hashlib.sha512(b"".join(sorted([a.fingerprint(), b.fingerprint()]))).digest()
    digits = "".join(f"{int.from_bytes(d[i:i + 3], 'big') % 100000:05d}" for i in range(0, 36, 3))
    return " ".join(digits[i:i + 5] for i in range(0, 60, 5))


def _spk_message(identity: IdentityPublic, spk: bytes) -> bytes:
    return b"X3DH-SPK-v1" + identity.dh + spk     # подпись привязывает prekey к обоим ключам идентичности


@dataclass(frozen=True)
class PrekeyBundle:
    identity: IdentityPublic
    spk_id: int
    spk: bytes
    spk_sig: bytes
    opk_id: int | None = None
    opk: bytes | None = None


@dataclass(frozen=True)
class InitialHeader:
    identity: IdentityPublic    # IK_A
    ek: bytes
    spk_id: int
    opk_id: int | None


class PrekeyStore:
    """Приватная часть prekey-ключей получателя."""

    def __init__(self, identity: IdentityKeyPair, spk_id: int = 1):
        self.identity = identity
        self._spks: dict[int, tuple[bytes, bytes, bytes]] = {}     # id -> (priv, pub, подпись)
        self.spk_id = spk_id - 1
        self._new_spk()
        self._opks: dict[int, bytes] = {}
        self._next = 1000

    def _new_spk(self):
        self.spk_id += 1
        priv, pub = _gen()
        self._spks[self.spk_id] = (priv, pub, self.identity.sign(_spk_message(self.identity.public, pub)))

    def rotate_spk(self):
        """Ротация signed prekey. Предыдущий остаётся ровно на одно поколение (для сообщений «в полёте»), старше - стирается.
        Компрометация SPK позволяет выдавать себя за кого угодно перед владельцем (см. formal-verification), поэтому
        его срок жизни надо ограничивать."""
        old = self.spk_id
        self._new_spk()
        for i in [i for i in self._spks if i not in (old, self.spk_id)]:
            del self._spks[i]

    def spk_keys(self, spk_id: int) -> tuple[bytes, bytes]:
        try:
            priv, pub, _ = self._spks[spk_id]
        except KeyError:
            raise E2EEError("неизвестный или устаревший signed prekey")
        return priv, pub

    @property
    def spk(self) -> bytes:
        return self._spks[self.spk_id][1]

    @property
    def spk_sig(self) -> bytes:
        return self._spks[self.spk_id][2]

    def new_opks(self, n: int) -> list[tuple[int, bytes]]:
        out = []
        for _ in range(n):
            priv, pub = _gen()
            self._next += 1
            self._opks[self._next] = priv
            out.append((self._next, pub))
        return out

    def take_opk(self, opk_id: int) -> bytes:
        try:
            return self._opks.pop(opk_id)          # одноразовый: после использования приватный ключ удалён
        except KeyError:
            raise E2EEError("неизвестный или уже использованный одноразовый prekey")

    @property
    def spk_priv(self) -> bytes:
        return self._spks[self.spk_id][0]


def x3dh_initiate(ik_a: IdentityKeyPair, bundle: PrekeyBundle):
    try:
        Ed25519PublicKey.from_public_bytes(bundle.identity.sig).verify(
            bundle.spk_sig, _spk_message(bundle.identity, bundle.spk))
    except (InvalidSignature, ValueError):
        raise E2EEError("подпись signed prekey недействительна")
    ek_priv, ek_pub = _gen()
    parts = [_dh(ik_a.dh_priv, bundle.spk), _dh(ek_priv, bundle.identity.dh), _dh(ek_priv, bundle.spk)]
    if bundle.opk is not None:
        parts.append(_dh(ek_priv, bundle.opk))
    sk = _hkdf(b"\xff" * 32 + b"".join(parts), bytes(32), b"X3DH-v1", 32)
    ad = ik_a.public.dh + bundle.identity.dh
    return sk, ad, InitialHeader(ik_a.public, ek_pub, bundle.spk_id, bundle.opk_id)


def x3dh_respond(store: PrekeyStore, header: InitialHeader):
    spk_priv, _ = store.spk_keys(header.spk_id)
    parts = [_dh(spk_priv, header.identity.dh), _dh(store.identity.dh_priv, header.ek),
             _dh(spk_priv, header.ek)]
    if header.opk_id is not None:
        parts.append(_dh(store.take_opk(header.opk_id), header.ek))
    sk = _hkdf(b"\xff" * 32 + b"".join(parts), bytes(32), b"X3DH-v1", 32)
    return sk, header.identity.dh + store.identity.public.dh


# ---------- Double Ratchet ----------
def _kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    out = _hkdf(dh_out, rk, b"DR-RK-v1", 64)
    return out[:32], out[32:]


def _kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    return hmac.new(ck, b"\x02", hashlib.sha256).digest(), hmac.new(ck, b"\x01", hashlib.sha256).digest()   # (ck', mk)


def _aead_key(mk: bytes) -> tuple[bytes, bytes]:
    okm = _hkdf(mk, bytes(32), b"DR-MSG-v1", 44)
    return okm[:32], okm[32:]


HEADER_LEN = 32 + 4 + 4


def _pack_header(dh: bytes, pn: int, n: int) -> bytes:
    return dh + struct.pack(">II", pn, n)


def _parse_header(h: bytes):
    if len(h) != HEADER_LEN:
        raise DecryptionError("неверная длина заголовка")
    return h[:32], *struct.unpack(">II", h[32:])


@dataclass
class _State:
    dhs_priv: bytes
    dhs_pub: bytes
    dhr: bytes | None
    rk: bytes
    cks: bytes | None
    ckr: bytes | None
    ns: int = 0
    nr: int = 0
    pn: int = 0
    skipped: OrderedDict = None


class Ratchet:
    def __init__(self, state: _State, ad: bytes, max_skip: int = MAX_SKIP):
        self._s, self.ad, self.max_skip = state, ad, max_skip

    @classmethod
    def init_alice(cls, sk: bytes, bob_spk_pub: bytes, ad: bytes, max_skip: int = MAX_SKIP):
        priv, pub = _gen()
        rk, cks = _kdf_rk(sk, _dh(priv, bob_spk_pub))
        return cls(_State(priv, pub, bob_spk_pub, rk, cks, None, skipped=OrderedDict()), ad, max_skip)

    @classmethod
    def init_bob(cls, sk: bytes, spk_priv: bytes, spk_pub: bytes, ad: bytes, max_skip: int = MAX_SKIP):
        return cls(_State(spk_priv, spk_pub, None, sk, None, None, skipped=OrderedDict()), ad, max_skip)

    def snapshot(self):
        """Копия состояния - для тестов 'атакующий украл состояние'."""
        return copy.deepcopy(self)

    def _full_ad(self, header: bytes, extra: bytes) -> bytes:
        return struct.pack(">I", len(self.ad)) + self.ad + header + extra

    def encrypt(self, plaintext: bytes, extra_ad: bytes = b"") -> tuple[bytes, bytes]:
        s = self._s
        if s.cks is None:
            raise E2EEError("отправлять можно только после первого полученного сообщения (нет цепочки отправки)")
        s.cks, mk = _kdf_ck(s.cks)
        header = _pack_header(s.dhs_pub, s.pn, s.ns)
        s.ns += 1
        key, nonce = _aead_key(mk)
        return header, AESGCM(key).encrypt(nonce, plaintext, self._full_ad(header, extra_ad))

    def decrypt(self, header: bytes, ciphertext: bytes, extra_ad: bytes = b"") -> bytes:
        dh, pn, n = _parse_header(header)
        st = copy.deepcopy(self._s)            # рабочая копия: исходное состояние не трогаем до успеха
        mk = st.skipped.pop((dh, n), None)
        if mk is None:
            if st.dhr == dh and n < st.nr:
                raise DecryptionError("повтор или слишком старое сообщение")
            if st.dhr != dh:
                self._skip(st, pn)
                self._dh_ratchet(st, dh)
            self._skip(st, n)
            st.ckr, mk = _kdf_ck(st.ckr)
            st.nr += 1
        key, nonce = _aead_key(mk)
        try:
            pt = AESGCM(key).decrypt(nonce, ciphertext, self._full_ad(header, extra_ad))
        except InvalidTag:
            raise DecryptionError("аутентификация не пройдена")
        self._s = st                            # коммит только после успешной проверки
        return pt

    def _skip(self, st: _State, until: int):
        if st.ckr is None:
            return
        if until - st.nr > self.max_skip:
            raise SkipLimitExceeded(f"пропущено больше {self.max_skip} сообщений")
        while st.nr < until:
            st.ckr, mk = _kdf_ck(st.ckr)
            st.skipped[(st.dhr, st.nr)] = mk
            st.nr += 1
            while len(st.skipped) > MAX_STORED_SKIPPED:
                st.skipped.popitem(last=False)

    def _dh_ratchet(self, st: _State, dh: bytes):
        st.pn, st.ns, st.nr = st.ns, 0, 0
        st.dhr = dh
        st.rk, st.ckr = _kdf_rk(st.rk, _dh(st.dhs_priv, dh))
        st.dhs_priv, st.dhs_pub = _gen()
        st.rk, st.cks = _kdf_rk(st.rk, _dh(st.dhs_priv, dh))
