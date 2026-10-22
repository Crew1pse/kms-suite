"""DSSE (Dead Simple Signing Envelope): подпись над PAE, а не над «сырым» JSON; тип полезной нагрузки входит в подпись."""
import base64
import json
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey


class DsseError(Exception): pass


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def sign_envelope(payload: bytes, payload_type: str, signers: list[tuple[str, Callable[[bytes], bytes]]]) -> dict:
    """signers: [(keyid, fn(msg)->64-байтная Ed25519-подпись)]. fn может быть и пороговой подписью FROST."""
    msg = pae(payload_type, payload)
    return {"payloadType": payload_type, "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": k, "sig": base64.b64encode(fn(msg)).decode()} for k, fn in signers]}


ED25519, MLDSA65 = "ed25519", "ml-dsa-65"


def _verifier(entry):
    """entry: bytes (Ed25519, обратная совместимость) или (alg, bytes). Возвращает (alg, fn(sig, msg))."""
    alg, raw = (ED25519, entry) if isinstance(entry, (bytes, bytearray)) else entry
    if alg == ED25519:
        return alg, Ed25519PublicKey.from_public_bytes(raw).verify
    if alg == MLDSA65:
        return alg, MLDSA65PublicKey.from_public_bytes(raw).verify
    raise DsseError(f"неизвестный алгоритм {alg!r}")


def verify_envelope(env: dict, trusted: dict, threshold: int = 1,
                    expected_type: str | None = None, require_algs: tuple = ()) -> bytes:
    """trusted: keyid -> public key Ed25519 (bytes) или (alg, bytes) для ml-dsa-65.
    Нужно >= threshold РАЗНЫХ доверенных ключей с валидной подписью, и по одной валидной подписи каждого алгоритма из
    require_algs (гибрид: подделка требует сломать ВСЕ перечисленные схемы)."""
    try:
        ptype, payload = env["payloadType"], base64.b64decode(env["payload"], validate=True)
        sigs = env["signatures"]
    except (KeyError, ValueError, TypeError):
        raise DsseError("битый конверт")
    if expected_type is not None and ptype != expected_type:
        raise DsseError(f"неожиданный payloadType {ptype!r}")
    msg, good = pae(ptype, payload), {}
    for s in sigs if isinstance(sigs, list) else []:
        try:
            keyid, sig = s["keyid"], base64.b64decode(s["sig"], validate=True)
            entry = trusted.get(keyid)
            if entry is None:
                continue
            alg, verify = _verifier(entry)
            verify(sig, msg)
            good[keyid] = alg                             # дубликаты одного ключа считаются один раз
        except (InvalidSignature, KeyError, ValueError, TypeError):
            continue
    if len(good) < threshold:
        raise DsseError(f"валидных подписей доверенных ключей {len(good)} из {threshold} требуемых")
    missing = set(require_algs) - set(good.values())
    if missing:
        raise DsseError(f"нет валидной подписи алгоритма {sorted(missing)}")
    return payload
