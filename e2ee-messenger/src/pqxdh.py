"""PQXDH: гибрид X3DH + ML-KEM-768 (FIPS 203). Ключ сессии секретен, пока устойчива ХОТЯ БЫ ОДНА из двух частей:
классический X25519 или постквантовый ML-KEM. Защищает от схемы «записать сейчас, взломать потом».

Отличия от X3DH: в bundle есть подписанный ключ инкапсуляции ML-KEM (последний-резерв и опционально одноразовый),
в начальном сообщении - шифртекст KEM, в KDF добавлен общий секрет KEM. Дальше обычный Double Ratchet."""
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from kyber_py.ml_kem import ML_KEM_768

from e2ee import (E2EEError, IdentityKeyPair, IdentityPublic, InitialHeader, PrekeyBundle, PrekeyStore,
                  _dh, _gen, _hkdf, _spk_message)

EK_LEN, CT_LEN, SS_LEN = 1184, 1088, 32


def _pq_message(identity: IdentityPublic, kind: bytes, ek: bytes) -> bytes:
    return b"PQXDH-KEM-v1" + kind + identity.dh + ek      # подпись привязана к ключу идентичности и роли ключа


@dataclass(frozen=True)
class PQBundle:
    base: PrekeyBundle              # классическая часть (IK, SPK, OPK)
    pq_id: int
    pq_ek: bytes
    pq_sig: bytes
    pq_one_time: bool = False


@dataclass(frozen=True)
class PQInitialHeader:
    base: InitialHeader
    pq_id: int
    pq_ct: bytes


class PQPrekeyStore:
    """Приватные ключи декапсуляции. Одноразовый ключ удаляется после использования, last-resort остаётся."""

    def __init__(self, identity: IdentityKeyPair):
        self.identity = identity
        self._keys: dict[int, tuple[bytes, bool]] = {}
        self._next = 5000

    def new_key(self, one_time: bool) -> tuple[int, bytes, bytes]:
        ek, dk = ML_KEM_768.keygen()
        self._next += 1
        self._keys[self._next] = (dk, one_time)
        sig = self.identity.sign(_pq_message(self.identity.public, b"OT" if one_time else b"LR", ek))
        return self._next, ek, sig

    def take(self, pq_id: int) -> bytes:
        try:
            dk, one_time = self._keys[pq_id]
        except KeyError:
            raise E2EEError("неизвестный PQ prekey")
        if one_time:
            del self._keys[pq_id]
        return dk


def _kdf(dh_parts: list[bytes], ss: bytes) -> bytes:
    return _hkdf(b"\xff" * 32 + b"".join(dh_parts) + ss, bytes(32), b"PQXDH-v1", 32)


def pqxdh_initiate(ik_a: IdentityKeyPair, b: PQBundle):
    try:
        Ed25519PublicKey.from_public_bytes(b.base.identity.sig).verify(
            b.base.spk_sig, _spk_message(b.base.identity, b.base.spk))
    except (InvalidSignature, ValueError):
        raise E2EEError("подпись signed prekey недействительна")
    try:
        Ed25519PublicKey.from_public_bytes(b.base.identity.sig).verify(
            b.pq_sig, _pq_message(b.base.identity, b"OT" if b.pq_one_time else b"LR", b.pq_ek))
    except (InvalidSignature, ValueError):
        raise E2EEError("подпись PQ prekey недействительна")
    if len(b.pq_ek) != EK_LEN:
        raise E2EEError("неверная длина ключа ML-KEM")
    ss, ct = ML_KEM_768.encaps(b.pq_ek)
    ek_priv, ek_pub = _gen()
    parts = [_dh(ik_a.dh_priv, b.base.spk), _dh(ek_priv, b.base.identity.dh), _dh(ek_priv, b.base.spk)]
    if b.base.opk is not None:
        parts.append(_dh(ek_priv, b.base.opk))
    sk = _kdf(parts, ss)
    ad = ik_a.public.dh + b.base.identity.dh
    return sk, ad, PQInitialHeader(InitialHeader(ik_a.public, ek_pub, b.base.spk_id, b.base.opk_id), b.pq_id, ct)


def pqxdh_respond(store: PrekeyStore, pq_store: PQPrekeyStore, h: PQInitialHeader):
    base = h.base
    spk_priv, _ = store.spk_keys(base.spk_id)
    if len(h.pq_ct) != CT_LEN:
        raise E2EEError("неверная длина шифртекста ML-KEM")
    parts = [_dh(spk_priv, base.identity.dh), _dh(store.identity.dh_priv, base.ek), _dh(spk_priv, base.ek)]
    if base.opk_id is not None:
        parts.append(_dh(store.take_opk(base.opk_id), base.ek))
    ss = ML_KEM_768.decaps(pq_store.take(h.pq_id), h.pq_ct)
    return _kdf(parts, ss), base.identity.dh + store.identity.public.dh
