"""Фаззинг и поведенческие тесты API узла (без сети: TestClient). CN-проверка тестируется отдельно."""
import secrets
import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, given, settings, strategies as st

import node
from feldman_vss import FeldmanVSS, Q

fuzz = settings(deadline=None, max_examples=60, suppress_health_check=[HealthCheck.function_scoped_fixture])


@pytest.fixture(scope="module")
def client():
    with TestClient(node.app, raise_server_exceptions=False) as c:   # lifespan создаёт таблицы
        yield c


@pytest.fixture()
def as_coordinator():
    node.app.dependency_overrides[node.require_coordinator] = lambda: None
    yield
    node.app.dependency_overrides.clear()


def good_payload(key_id, node_id=1, k=3, n=5):
    shares, comm = FeldmanVSS(k, n).generate_shares_and_commitments(secrets.randbelow(Q - 1) + 1)
    x, y = shares[node_id - 1]
    return {"key_id": key_id, "share_x": x, "share_y_hex": f"{y:064x}", "commitments": comm}


# ---------- авторизация ----------
@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/v1/shares/store", good_payload("a")),
    ("GET", "/api/v1/shares/retrieve/a", None),
    ("DELETE", "/api/v1/shares/a", None),
])
def test_no_peer_cn_is_forbidden(client, method, path, body):
    r = client.request(method, path, json=body)
    assert r.status_code == 403


def test_wrong_cn_forbidden(client):
    # имитируем соседний узел: scope["kms_peer_cn"] = "kms-node-2" задаёт транспортный слой; здесь - прямой вызов зависимости
    class Req:  scope = {"kms_peer_cn": "kms-node-2"}
    with pytest.raises(Exception) as e:
        node.require_coordinator(Req())
    assert getattr(e.value, "status_code", None) == 403
    class Ok:  scope = {"kms_peer_cn": node.COORDINATOR_CN}
    assert node.require_coordinator(Ok()) is None


# ---------- жизненный цикл ----------
def test_lifecycle(client, as_coordinator):
    p = good_payload("life-1")
    assert client.post("/api/v1/shares/store", json=p).status_code == 200
    assert client.post("/api/v1/shares/store", json=p).status_code == 409
    r = client.get("/api/v1/shares/retrieve/life-1")
    assert r.status_code == 200 and r.json()["share_y_hex"] == p["share_y_hex"]
    assert client.delete("/api/v1/shares/life-1").json()["status"] == "shredded"
    assert client.get("/api/v1/shares/retrieve/life-1").status_code == 410
    assert client.delete("/api/v1/shares/life-1").json()["status"] == "already_shredded"
    assert client.post("/api/v1/shares/store", json=p).status_code == 409   # tombstone держит


def test_shred_unknown_key_makes_tombstone(client, as_coordinator):
    assert client.delete("/api/v1/shares/never-seen").status_code == 200
    assert client.post("/api/v1/shares/store", json=good_payload("never-seen")).status_code == 409


def test_shredded_row_has_no_secret(client, as_coordinator):
    import asyncio, sqlite3, glob
    p = good_payload("wipe-1")
    client.post("/api/v1/shares/store", json=p); client.delete("/api/v1/shares/wipe-1")
    db = glob.glob(f"{node.DB_DIR}/node_{node.NODE_ID}.db")[0]
    row = sqlite3.connect(db).execute("select share_x, share_y_hex, status from vault_shares where key_id='wipe-1'").fetchone()
    assert row == (None, None, "SHREDDED")


# ---------- фаззинг: ни при каких входах не 5xx ----------
json_scalar = st.one_of(st.none(), st.booleans(), st.integers(-2**70, 2**70), st.floats(allow_nan=False, allow_infinity=False), st.text(max_size=100))
junk_payload = st.fixed_dictionaries({}, optional={
    "key_id": json_scalar, "share_x": json_scalar, "share_y_hex": json_scalar,
    "commitments": st.one_of(json_scalar, st.lists(json_scalar, max_size=15))})


@fuzz
@given(junk_payload)
def test_store_junk_never_5xx(client, as_coordinator, body):
    assert client.post("/api/v1/shares/store", json=body).status_code < 500


@fuzz
@given(st.text(max_size=300))
def test_key_id_any_text_never_5xx(client, as_coordinator, key_id):
    from urllib.parse import quote
    k = quote(key_id, safe="")
    assert client.get(f"/api/v1/shares/retrieve/{k}").status_code < 500
    assert client.delete(f"/api/v1/shares/{k}").status_code < 500


@fuzz
@given(st.text(max_size=300))
def test_store_with_arbitrary_key_id(client, as_coordinator, key_id):
    p = good_payload(key_id)
    assert client.post("/api/v1/shares/store", json=p).status_code < 500


@fuzz
@given(st.lists(st.text(alphabet="0123456789abcdef", min_size=66, max_size=66), min_size=3, max_size=3))
def test_valid_length_garbage_commitments_rejected(client, as_coordinator, comm):
    p = good_payload("fz-comm"); p["key_id"] = "fz-" + secrets.token_hex(4); p["commitments"] = comm
    r = client.post("/api/v1/shares/store", json=p)
    assert r.status_code == 400


def test_malformed_and_huge_bodies(client, as_coordinator):
    h = {"content-type": "application/json"}
    for raw in (b"", b"{", b"null", b"[]", b'{"key_id":' + b"1" * 100000 + b"}", b"\xff\xfe"):
        assert client.post("/api/v1/shares/store", content=raw, headers=h).status_code < 500


def test_share_belongs_to_other_node_rejected(client, as_coordinator):
    assert client.post("/api/v1/shares/store", json=good_payload("o2", node_id=2)).status_code == 400


def test_commitments_for_other_secret_rejected(client, as_coordinator):
    a, b = good_payload("m1"), good_payload("m1b")
    a["commitments"] = b["commitments"]
    assert client.post("/api/v1/shares/store", json=a).status_code == 400


@pytest.mark.parametrize("k_commit", [1, 2, 4, 5])
def test_valid_but_wrong_number_of_commitments_rejected(client, as_coordinator, k_commit):
    """Коммитменты корректного полинома другой степени проходят verify_share - длину обязан ограничить узел."""
    shares, comm = FeldmanVSS(k_commit, 5).generate_shares_and_commitments(secrets.randbelow(Q - 1) + 1)
    x, y = shares[0]
    p = {"key_id": f"len-{k_commit}", "share_x": x, "share_y_hex": f"{y:064x}", "commitments": comm}
    assert client.post("/api/v1/shares/store", json=p).status_code == 400


def test_spiffe_mode_authorizes_by_uri_san_only(monkeypatch):
    import pytest as _p
    from fastapi import HTTPException
    monkeypatch.setattr(node, "COORDINATOR_SPIFFE_ID", "spiffe://prod.example/kms/coordinator")

    class R:
        def __init__(self, **s): self.scope = s
    node.require_coordinator(R(kms_peer_spiffe="spiffe://prod.example/kms/coordinator"))
    # CN больше не даёт доступа в режиме SPIFFE
    for scope in ({"kms_peer_cn": node.COORDINATOR_CN}, {"kms_peer_spiffe": "spiffe://prod.example/kms/other"},
                  {"kms_peer_spiffe": None}, {}):
        with _p.raises(HTTPException) as e:
            node.require_coordinator(R(**scope))
        assert e.value.status_code == 403
