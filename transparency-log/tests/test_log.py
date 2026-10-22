import base64, json, sqlite3, threading
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from merkle import verify_inclusion, verify_consistency
from monitor import (Monitor, LogClient, MonitorAlert, SignatureInvalid, RollbackDetected, ForkDetected,
                     InconsistentHistory, InclusionFailed)
from server import create_app
from tlog import TransparencyLog, LogCorrupted, verify_sth_signature

TOKEN = "s3cret-append-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def event(i, **kw):
    return json.dumps({"v": 1, "op": "store", "n": i, **kw}, sort_keys=True).encode()


@pytest.fixture()
def key():
    return Ed25519PrivateKey.generate()


@pytest.fixture()
def log(tmp_path, key):
    return TransparencyLog(str(tmp_path / "log.db"), key)


@pytest.fixture()
def client(log):
    return TestClient(create_app(log, TOKEN))


# ---------- ядро лога ----------
def test_append_and_signed_tree_head(log, key):
    for i in range(5):
        idx, sth = log.append(event(i))
        assert idx == i and sth["tree_size"] == i + 1
        assert verify_sth_signature(key.public_key(), sth)
    assert len(log) == 5


def test_sth_tampering_and_wrong_key_rejected(log, key):
    _, sth = log.append(event(0))
    pub = key.public_key()
    for field, val in (("tree_size", 2), ("timestamp", sth["timestamp"] + 1), ("root_hash", "00" * 32)):
        assert not verify_sth_signature(pub, {**sth, field: val})
    assert not verify_sth_signature(Ed25519PrivateKey.generate().public_key(), sth)
    assert not verify_sth_signature(pub, {"tree_size": 1})


def test_storage_is_append_only(tmp_path, key):
    path = str(tmp_path / "l.db"); lg = TransparencyLog(path, key); lg.append(event(0))
    db = sqlite3.connect(path)
    for sql in ("UPDATE entries SET data = x'00'", "DELETE FROM entries", "UPDATE sths SET tree_size = 9", "DELETE FROM sths"):
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            db.execute(sql)


def test_reopen_preserves_state(tmp_path, key):
    path = str(tmp_path / "l.db"); a = TransparencyLog(path, key)
    for i in range(7): a.append(event(i))
    root = a.tree.root()
    b = TransparencyLog(path, key)
    assert len(b) == 7 and b.tree.root() == root and b.latest_sth()["root_hash"] == root.hex()


def _bypass(path, *sql):
    db = sqlite3.connect(path)
    for t in ("entries_no_update", "entries_no_delete", "sths_no_update", "sths_no_delete"):
        db.execute(f"DROP TRIGGER {t}")
    for s in sql: db.execute(s)
    db.commit(); db.close()


def test_selfcheck_detects_edited_entry_data(tmp_path, key):
    path = str(tmp_path / "l.db"); lg = TransparencyLog(path, key)
    for i in range(4): lg.append(event(i))
    _bypass(path, "UPDATE entries SET data = x'41' WHERE idx = 1")          # данные изменены, хэш листа нет
    with pytest.raises(LogCorrupted):
        TransparencyLog(path, key)


def test_selfcheck_detects_edited_entry_with_recomputed_hash(tmp_path, key):
    from merkle import leaf_hash
    path = str(tmp_path / "l.db"); lg = TransparencyLog(path, key)
    for i in range(4): lg.append(event(i))
    _bypass(path, f"UPDATE entries SET data = x'41', leaf_hash = x'{leaf_hash(b'A').hex()}' WHERE idx = 1")
    with pytest.raises(LogCorrupted, match="не совпадает"):                 # корень расходится с подписанным STH
        TransparencyLog(path, key)


def test_selfcheck_detects_truncation_and_forged_sth(tmp_path, key):
    path = str(tmp_path / "l.db"); lg = TransparencyLog(path, key)
    for i in range(4): lg.append(event(i))
    _bypass(path, "DELETE FROM entries WHERE idx = 3")
    with pytest.raises(LogCorrupted):
        TransparencyLog(path, key)


def test_selfcheck_detects_bad_signature(tmp_path, key):
    path = str(tmp_path / "l.db"); lg = TransparencyLog(path, key); lg.append(event(0))
    _bypass(path, "UPDATE sths SET signature = zeroblob(64)")
    with pytest.raises(LogCorrupted, match="подпись"):
        TransparencyLog(path, key)


def test_concurrent_appends(log, key):
    errs = []
    def work(k):
        try:
            for j in range(10): log.append(event(k * 100 + j))
        except Exception as e: errs.append(e)
    ts = [threading.Thread(target=work, args=(k,)) for k in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert not errs and len(log) == 80
    datas = [log.get_entry(i) for i in range(80)]
    assert len(set(datas)) == 80
    from merkle import MerkleTree
    t = MerkleTree()
    for d in datas: t.append(d)
    assert t.root() == log.tree.root()


# ---------- HTTP API ----------
def test_api_auth_and_limits(client):
    assert client.post("/v1/entries", content=b"x").status_code == 401
    assert client.post("/v1/entries", content=b"x", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/v1/entries", content=b"", headers=AUTH).status_code == 400
    assert client.post("/v1/entries", content=b"x" * 70000, headers=AUTH).status_code == 400
    r = client.post("/v1/entries", content=b"hello", headers=AUTH)
    assert r.status_code == 200 and r.json()["index"] == 0
    assert client.get("/v1/entries/0").json()["data"] == base64.b64encode(b"hello").decode()
    assert client.get("/v1/entries/5").status_code == 404


def test_api_requires_nonempty_token(log):
    with pytest.raises(ValueError):
        create_app(log, "")


def test_api_proofs_verify_end_to_end(client):
    for i in range(13): client.post("/v1/entries", content=event(i), headers=AUTH)
    sth = client.get("/v1/sth").json()
    root, size = bytes.fromhex(sth["root_hash"]), sth["tree_size"]
    assert size == 13
    for i in range(13):
        p = client.get("/v1/proof/inclusion", params={"index": i, "tree_size": size}).json()["audit_path"]
        assert verify_inclusion(event(i), i, size, [bytes.fromhex(x) for x in p], root)
    old = {"tree_size": 5, "root_hash": None}
    for first in (1, 5, 8, 12, 13):
        c = client.get("/v1/proof/consistency", params={"first": first, "second": 13}).json()["consistency_path"]
        # корень старого дерева восстанавливаем независимо - из тех же записей
        from merkle import MerkleTree
        t = MerkleTree()
        for i in range(first): t.append(event(i))
        assert verify_consistency(first, 13, t.root(), root, [bytes.fromhex(x) for x in c])
    for params in ({"index": 13, "tree_size": 13}, {"index": 0, "tree_size": 14}, {"index": -1, "tree_size": 5}):
        assert client.get("/v1/proof/inclusion", params=params).status_code in (400, 422)
    for params in ({"first": 0, "second": 3}, {"first": 5, "second": 3}, {"first": 3, "second": 99}):
        assert client.get("/v1/proof/consistency", params=params).status_code in (400, 422)


# ---------- монитор: честный журнал ----------
class Switch:
    """Позволяет подменить сервер под монитором (имитация нечестного оператора)."""
    def __init__(self, c): self.c = c
    def get(self, *a, **k): return self.c.get(*a, **k)


def grow(client, start, n):
    for i in range(start, start + n):
        assert client.post("/v1/entries", content=event(i), headers=AUTH).status_code == 200


def test_monitor_follows_honest_log(client, key):
    mon = Monitor(LogClient(client), key.public_key())
    seen = []
    grow(client, 0, 5); seen += [d for _, d in mon.new_entries()]
    grow(client, 5, 7); seen += [d for _, d in mon.new_entries()]
    grow(client, 12, 1); seen += [d for _, d in mon.new_entries()]
    assert seen == [event(i) for i in range(13)]
    assert mon.trusted["tree_size"] == 13
    mon.check_inclusion(event(4), 4)
    with pytest.raises(InclusionFailed):
        mon.check_inclusion(event(99), 4)
    mon.update()   # повторное обновление без роста допустимо


def test_monitor_needs_trusted_sth_for_inclusion(client, key):
    with pytest.raises(MonitorAlert):
        Monitor(LogClient(client), key.public_key()).check_inclusion(b"x", 0)


# ---------- монитор: атаки нечестного оператора ----------
def make_evil(tmp_path, signer, entries, name="evil.db"):
    lg = TransparencyLog(str(tmp_path / name), signer)
    for e in entries: lg.append(e)
    return TestClient(create_app(lg, TOKEN))


def test_monitor_detects_history_rewrite(tmp_path, client, key):
    sw = Switch(client); mon = Monitor(LogClient(sw), key.public_key())
    grow(client, 0, 8); mon.update()
    # оператор владеет ключом подписи и пересобирает журнал с изменённой записью №2 и теми же + новыми записями
    evil = make_evil(tmp_path, key, [event(i) if i != 2 else event(2, op="nothing-happened") for i in range(12)])
    sw.c = evil
    with pytest.raises(InconsistentHistory):
        mon.update()


def test_monitor_detects_rollback(tmp_path, client, key):
    sw = Switch(client); mon = Monitor(LogClient(sw), key.public_key())
    grow(client, 0, 8); mon.update()
    sw.c = make_evil(tmp_path, key, [event(i) for i in range(5)])      # честный префикс, но короче
    with pytest.raises(RollbackDetected):
        mon.update()


def test_monitor_detects_fork_same_size(tmp_path, client, key):
    sw = Switch(client); mon = Monitor(LogClient(sw), key.public_key())
    grow(client, 0, 8); mon.update()
    sw.c = make_evil(tmp_path, key, [event(i) if i != 7 else event(7, extra="x") for i in range(8)])
    with pytest.raises(ForkDetected):
        mon.update()


def test_monitor_rejects_wrong_signing_key(tmp_path, client, key):
    sw = Switch(client); mon = Monitor(LogClient(sw), key.public_key())
    grow(client, 0, 3); mon.update()
    sw.c = make_evil(tmp_path, Ed25519PrivateKey.generate(), [event(i) for i in range(5)])
    with pytest.raises(SignatureInvalid):
        mon.update()


def test_monitor_detects_lying_entry_content(client, key):
    grow(client, 0, 6)
    lc = LogClient(client)
    mon = Monitor(lc, key.public_key())
    real = lc.entry
    lc.entry = lambda i: b"forged" if i == 3 else real(i)   # сервер отдаёт не то, что в дереве
    with pytest.raises(InclusionFailed):
        list(mon.new_entries())


def test_monitor_detects_bogus_consistency_proof(client, key):
    lc = LogClient(client); mon = Monitor(lc, key.public_key())
    grow(client, 0, 4); mon.update(); grow(client, 4, 4)
    lc.consistency = lambda a, b: [bytes(32)] * 3
    with pytest.raises(InconsistentHistory):
        mon.update()
