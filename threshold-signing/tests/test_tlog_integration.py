"""Журнал прозрачности подписывает STH пороговым ключом: приватный ключ журнала не существует нигде целиком,
а проверяющий видит обычную подпись Ed25519."""
import json, random
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient
import frost
from helpers import run_dkg
from monitor import Monitor, LogClient, SignatureInvalid
from server import create_app
from tlog import TransparencyLog, verify_sth_signature


class ThresholdKey:
    """Утиная типизация под Ed25519PrivateKey, которым пользуется TransparencyLog: sign() + public_key()."""
    def __init__(self, shares, pkg, t):
        self.shares, self.pkg, self.t = shares, pkg, t
        self.signatures = 0

    def public_key(self):
        return Ed25519PublicKey.from_public_bytes(self.pkg.group_public_key)

    def sign(self, message: bytes) -> bytes:
        ids = random.sample(sorted(self.shares), self.t)        # каждый раз другой кворум
        signers = {i: frost.Signer(self.shares[i]) for i in ids}
        coms = [s.commit() for s in signers.values()]
        sig = frost.aggregate(self.pkg, message, coms, [s.sign(message, coms) for s in signers.values()])
        self.signatures += 1
        return sig


@pytest.fixture()
def tkey():
    shares, pkgs, *_ = run_dkg(5, 3, session=b"tlog-signing-key")
    return ThresholdKey(shares, pkgs[1], 3)


def test_log_signed_by_threshold_key_passes_standard_checks(tmp_path, tkey):
    log = TransparencyLog(str(tmp_path / "l.db"), tkey)
    client = TestClient(create_app(log, "tok"))
    for i in range(6):
        assert client.post("/v1/entries", content=json.dumps({"n": i}).encode(),
                           headers={"Authorization": "Bearer tok"}).status_code == 200
    sth = client.get("/v1/sth").json()
    assert verify_sth_signature(tkey.public_key(), sth)                 # штатный верификатор журнала
    assert tkey.signatures >= 6
    mon = Monitor(LogClient(client), tkey.public_key())                 # монитор знает только публичный ключ
    assert [json.loads(d)["n"] for _, d in mon.new_entries()] == list(range(6))


def test_threshold_signed_log_survives_restart_and_selfcheck(tmp_path, tkey):
    path = str(tmp_path / "l.db")
    a = TransparencyLog(path, tkey)
    for i in range(4): a.append(b"e%d" % i)
    b = TransparencyLog(path, tkey)                                     # самопроверка проверяет подписи пороговым ключом
    assert len(b) == 4


def test_signature_from_other_threshold_key_is_rejected_by_monitor(tmp_path, tkey):
    other_shares, other_pkgs, *_ = run_dkg(5, 3, session=b"another-key")
    evil = TransparencyLog(str(tmp_path / "e.db"), ThresholdKey(other_shares, other_pkgs[1], 3))
    evil.append(b"x")
    mon = Monitor(LogClient(TestClient(create_app(evil, "t"))), tkey.public_key())
    with pytest.raises(SignatureInvalid):
        mon.update()
