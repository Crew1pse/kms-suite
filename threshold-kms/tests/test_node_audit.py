"""Узел пишет в журнал прозрачности ДО операции; нет записи -> 503 и состояние не меняется.
Интеграционный тест подключает настоящий журнал (kms-suite/transparency-log) и монитор."""
import json, os, secrets, sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "transparency-log", "src"))
import node
from audit_client import AuditUnavailable
from feldman_vss import FeldmanVSS, Q


def payload(key_id):
    shares, comm = FeldmanVSS(3, 5).generate_shares_and_commitments(secrets.randbelow(Q - 1) + 1)
    x, y = shares[0]
    return {"key_id": key_id, "share_x": x, "share_y_hex": f"{y:064x}", "commitments": comm}


@pytest.fixture()
def client():
    node.app.dependency_overrides[node.require_coordinator] = lambda: None
    with TestClient(node.app, raise_server_exceptions=False) as c:
        yield c
    node.app.dependency_overrides.clear()


@pytest.fixture()
def restore_sink():
    old = node.audit_sink
    yield
    node.audit_sink = old


def test_events_recorded_before_each_operation(client, restore_sink):
    events = []
    async def sink(e): events.append(json.loads(e))
    node.audit_sink = sink
    p = payload("secret-key-name-42")
    client.post("/api/v1/shares/store", json=p); client.get("/api/v1/shares/retrieve/secret-key-name-42")
    client.delete("/api/v1/shares/secret-key-name-42")
    assert [e["op"] for e in events] == ["store", "retrieve", "shred"]
    assert all(e["node_id"] == node.NODE_ID and e["v"] == 1 for e in events)
    raw = json.dumps(events)
    assert "secret-key-name-42" not in raw and p["share_y_hex"] not in raw       # ни имени ключа, ни доли
    assert len({e["key_sha256"] for e in events}) == 1 and len(events[0]["key_sha256"]) == 64


def test_audit_down_blocks_every_operation_and_changes_nothing(client, restore_sink):
    p = payload("guarded"); r = client.post("/api/v1/shares/store", json=p); assert r.status_code == 200, r.text
    async def down(e): raise AuditUnavailable("log is down")
    node.audit_sink = down
    assert client.post("/api/v1/shares/store", json=payload("new-while-down")).status_code == 503
    assert client.get("/api/v1/shares/retrieve/guarded").status_code == 503
    assert client.delete("/api/v1/shares/guarded").status_code == 503
    async def ok(e): return None
    node.audit_sink = ok
    assert client.get("/api/v1/shares/retrieve/new-while-down").status_code == 404     # store не прошёл
    assert client.get("/api/v1/shares/retrieve/guarded").status_code == 200            # delete не прошёл


def test_unexpected_sink_errors_do_not_open_the_gate(client, restore_sink):
    async def boom(e): raise RuntimeError("bug in sink")
    node.audit_sink = boom
    r = client.get("/api/v1/shares/retrieve/whatever")
    assert r.status_code >= 500        # fail-closed: операция не выполнена (не 200/404)


def test_end_to_end_with_real_log_and_monitor(client, restore_sink, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tlog import TransparencyLog
    from server import create_app
    from monitor import Monitor, LogClient
    key = Ed25519PrivateKey.generate()
    log = TransparencyLog(str(tmp_path / "audit.db"), key)
    async def sink(e): log.append(e)
    node.audit_sink = sink
    mon = Monitor(LogClient(TestClient(create_app(log, "t"))), key.public_key())
    client.post("/api/v1/shares/store", json=payload("e2e"))
    client.get("/api/v1/shares/retrieve/e2e")
    client.delete("/api/v1/shares/e2e")
    seen = [json.loads(d) for _, d in mon.new_entries()]
    assert [e["op"] for e in seen] == ["store", "retrieve", "shred"]
    client.get("/api/v1/shares/retrieve/e2e")                    # 410, но попытка тоже в журнале
    assert [json.loads(d)["op"] for _, d in mon.new_entries()] == ["retrieve"]


def test_app_survives_lifespan_restart():
    """Регресс: пул процессов жил на уровне модуля и умирал при остановке приложения."""
    node.app.dependency_overrides[node.require_coordinator] = lambda: None
    try:
        for n in range(2):
            with TestClient(node.app, raise_server_exceptions=False) as c:
                assert c.post("/api/v1/shares/store", json=payload(f"restart-{n}")).status_code == 200
    finally:
        node.app.dependency_overrides.clear()
