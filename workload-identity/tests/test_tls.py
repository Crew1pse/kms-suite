"""Настоящие TLS-рукопожатия на сокетах с SVID, а не имитация."""
import datetime as dt, socket, ssl, threading
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from svid import *
from spire import SpireServer, Agent

TD = "prod.example"
ID_S, ID_C = f"spiffe://{TD}/srv", f"spiffe://{TD}/client"
NOW = dt.datetime.now(dt.timezone.utc)


def ctx_for(agent, bundle, server_side):
    d = agent_dir[id(agent)]
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server_side else ssl.PROTOCOL_TLS_CLIENT)
    c.minimum_version = ssl.TLSVersion.TLSv1_3
    c.load_cert_chain(f"{d}/svid.crt", f"{d}/svid.key")
    c.load_verify_locations(cadata=b"".join(pem(x) for x in bundle).decode())
    c.verify_mode = ssl.CERT_REQUIRED
    if not server_side:
        c.check_hostname = False        # SPIFFE: имени хоста нет, проверяем SPIFFE ID вручную
    return c


agent_dir = {}


def mk_agent(s, spiffe, tmp_path, name, now=None):
    a = Agent(s, s.create_join_token(spiffe, now=now), now=now)
    d = tmp_path / name; a.write_files(d); agent_dir[id(a)] = str(d)
    return a


def handshake(srv_ctx, cli_ctx, bundle_srv, bundle_cli, expect_server_id=ID_S, expect_client_id=ID_C):
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(1)
    port = ls.getsockname()[1]; result = {}

    def serve():
        try:
            conn, _ = ls.accept()
            with srv_ctx.wrap_socket(conn, server_side=True) as t:
                der = t.getpeercert(binary_form=True)
                result["client_id"] = verify_svid(x509.load_der_x509_certificate(der), bundle_srv, TD, expect_client_id)
                t.sendall(b"pong")
        except Exception as e:
            result["server_err"] = e
        finally:
            ls.close()

    th = threading.Thread(target=serve); th.start()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with cli_ctx.wrap_socket(raw, server_hostname="localhost") as t:
                der = t.getpeercert(binary_form=True)
                result["server_id"] = verify_svid(x509.load_der_x509_certificate(der), bundle_cli, TD, expect_server_id)
                result["data"] = t.recv(4)
    except Exception as e:
        result["client_err"] = e
    th.join(5)
    return result


def test_mutual_tls_with_svids(tmp_path):
    s = SpireServer(TD); srv, cli = mk_agent(s, ID_S, tmp_path, "s"), mk_agent(s, ID_C, tmp_path, "c")
    r = handshake(ctx_for(srv, s.bundle(), True), ctx_for(cli, s.bundle(), False), s.bundle(), s.bundle())
    assert r.get("data") == b"pong" and r["client_id"] == ID_C and r["server_id"] == ID_S


def test_expired_client_svid_rejected_by_tls(tmp_path):
    s = SpireServer(TD); srv = mk_agent(s, ID_S, tmp_path, "s")
    old = NOW - dt.timedelta(hours=2)
    cli = mk_agent(s, ID_C, tmp_path, "c", now=old)       # выпущен 2 часа назад, TTL 10 минут
    r = handshake(ctx_for(srv, s.bundle(), True), ctx_for(cli, s.bundle(), False), s.bundle(), s.bundle())
    assert r.get("data") != b"pong" and ("server_err" in r or "client_err" in r)


def test_client_from_foreign_ca_rejected(tmp_path):
    s, evil = SpireServer(TD), SpireServer(TD)
    srv = mk_agent(s, ID_S, tmp_path, "s"); cli = mk_agent(evil, ID_C, tmp_path, "c")
    r = handshake(ctx_for(srv, s.bundle(), True), ctx_for(cli, s.bundle() + evil.bundle(), False), s.bundle(), s.bundle())
    assert "server_err" in r and r.get("data") != b"pong"


def test_wrong_identity_rejected_even_with_valid_cert(tmp_path):
    """Сертификат валиден, но принадлежит не тому сервису, который разрешён (авторизация по SPIFFE ID)."""
    s = SpireServer(TD); srv = mk_agent(s, ID_S, tmp_path, "s")
    other = mk_agent(s, f"spiffe://{TD}/intruder", tmp_path, "i")
    r = handshake(ctx_for(srv, s.bundle(), True), ctx_for(other, s.bundle(), False), s.bundle(), s.bundle())
    assert isinstance(r.get("server_err"), SvidError)


def test_client_without_cert_rejected(tmp_path):
    s = SpireServer(TD); srv = mk_agent(s, ID_S, tmp_path, "s")
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname = False
    c.load_verify_locations(cadata=b"".join(pem(x) for x in s.bundle()).decode())
    r = handshake(ctx_for(srv, s.bundle(), True), c, s.bundle(), s.bundle())
    assert "server_err" in r and r.get("data") != b"pong"


def test_rotated_ca_old_bundle_client_fails_new_works(tmp_path):
    s = SpireServer(TD); srv = mk_agent(s, ID_S, tmp_path, "s")
    old_bundle = s.bundle()
    s.rotate_ca()
    srv2 = Agent(s, s.create_join_token(ID_S)); d = tmp_path / "s2"; srv2.write_files(d); agent_dir[id(srv2)] = str(d)
    cli = mk_agent(s, ID_C, tmp_path, "c")
    ok = handshake(ctx_for(srv2, s.bundle(), True), ctx_for(cli, s.bundle(), False), s.bundle(), s.bundle())
    assert ok.get("data") == b"pong"
    stale = handshake(ctx_for(srv2, s.bundle(), True), ctx_for(cli, old_bundle, False), s.bundle(), old_bundle)
    assert stale.get("data") != b"pong"


def test_private_key_file_is_0600(tmp_path):
    import os, stat
    s = SpireServer(TD); a = mk_agent(s, ID_S, tmp_path, "s")
    assert stat.S_IMODE(os.stat(tmp_path / "s" / "svid.key").st_mode) == 0o600


def test_python_ssl_exposes_uri_san_as_kms_node_reads_it(tmp_path):
    """Ровно та выборка, которую делает threshold-kms/src/node.py: getpeercert()['subjectAltName'] -> URI."""
    s = SpireServer(TD); srv, cli = mk_agent(s, ID_S, tmp_path, "s"), mk_agent(s, ID_C, tmp_path, "c")
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(1); port = ls.getsockname()[1]; got = {}
    sctx = ctx_for(srv, s.bundle(), True)

    def serve():
        conn, _ = ls.accept()
        with sctx.wrap_socket(conn, server_side=True) as t:
            got["san"] = t.getpeercert().get("subjectAltName", ()); t.sendall(b"k")
    th = threading.Thread(target=serve); th.start()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx_for(cli, s.bundle(), False).wrap_socket(raw, server_hostname="x") as t:
            t.recv(1)
    th.join(5); ls.close()
    assert [v for k, v in got["san"] if k == "URI"] == [ID_C]
