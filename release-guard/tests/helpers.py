import os, copy
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tlog import TransparencyLog
from guard import *

REQ = "fastapi==0.143.3\nuvicorn==0.54.0\n# comment\nCryptography==50.0.2\n"


def raw(pk):
    return pk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def make_src(path, extra=None):
    os.makedirs(path / "pkg", exist_ok=True)
    (path / "pkg" / "a.py").write_text("print('a')\n")
    (path / "b.txt").write_text("hello\n")
    for k, v in (extra or {}).items():
        (path / k).write_text(v)
    return str(path)


class World:
    def __init__(self, tmp_path):
        self.k1, self.k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.logkey = Ed25519PrivateKey.generate()
        self.log = TransparencyLog(str(tmp_path / "log.db"), self.logkey)
        self.src = make_src(tmp_path / "src")
        self.signers = [("k1", self.k1.sign)]
        self.policy = Policy({"k1": raw(self.k1), "k2": raw(self.k2)}, 1, raw(self.logkey),
                             {"https://example.invalid/builder/1"})

    def release(self, signers=None, name="app", version="1.0"):
        return build_release(self.src, name, version, REQ, signers or self.signers, self.log)
