import base64, copy, gzip, os, tarfile, io, time
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from dsse import *
from repro import *
from sbom import *
from helpers import raw, make_src


def test_pae_official_vector():
    assert pae("http://example.com/HelloWorld", b"hello world") == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"


def test_pae_binds_type_and_length():
    assert pae("a", b"bc") != pae("ab", b"c")


def mk(n=3):
    ks = [Ed25519PrivateKey.generate() for _ in range(n)]
    return ks, {f"k{i}": raw(k) for i, k in enumerate(ks)}


def test_envelope_roundtrip_and_threshold():
    ks, trusted = mk()
    env = sign_envelope(b"payload", "t", [(f"k{i}", ks[i].sign) for i in range(2)])
    assert verify_envelope(env, trusted, 2, "t") == b"payload"
    with pytest.raises(DsseError):
        verify_envelope(env, trusted, 3, "t")


def test_duplicate_signature_of_one_key_counts_once():
    ks, trusted = mk()
    env = sign_envelope(b"p", "t", [("k0", ks[0].sign), ("k0", ks[0].sign)])
    with pytest.raises(DsseError):
        verify_envelope(env, trusted, 2, "t")


def test_unknown_key_and_bad_sig_ignored():
    ks, trusted = mk()
    env = sign_envelope(b"p", "t", [("k0", ks[0].sign), ("stranger", Ed25519PrivateKey.generate().sign)])
    with pytest.raises(DsseError):
        verify_envelope(env, trusted, 2, "t")
    env["signatures"][0]["sig"] = base64.b64encode(bytes(64)).decode()
    with pytest.raises(DsseError):
        verify_envelope(env, trusted, 1, "t")


def test_payload_or_type_tamper_rejected():
    ks, trusted = mk()
    env = sign_envelope(b"p", "t", [("k0", ks[0].sign)])
    e2 = copy.deepcopy(env); e2["payload"] = base64.b64encode(b"q").decode()
    with pytest.raises(DsseError): verify_envelope(e2, trusted, 1)
    e3 = copy.deepcopy(env); e3["payloadType"] = "other"
    with pytest.raises(DsseError): verify_envelope(e3, trusted, 1)
    with pytest.raises(DsseError): verify_envelope(env, trusted, 1, "expected-other")


@pytest.mark.parametrize("env", [{}, {"payloadType": "t"}, {"payloadType": "t", "payload": "!!", "signatures": []},
                                 {"payloadType": "t", "payload": "", "signatures": "x"}])
def test_malformed_envelopes(env):
    with pytest.raises(DsseError):
        verify_envelope(env, {}, 1)


# ---- воспроизводимость ----
def test_targz_deterministic_across_mtime_and_creation_order(tmp_path):
    a = make_src(tmp_path / "a"); b = tmp_path / "b"
    os.makedirs(b / "pkg"); (b / "b.txt").write_text("hello\n"); (b / "pkg" / "a.py").write_text("print('a')\n")
    os.utime(b / "b.txt", (1, 1)); time.sleep(0.01)
    assert deterministic_targz(a) == deterministic_targz(str(b))


def test_targz_changes_with_content_and_name(tmp_path):
    a = make_src(tmp_path / "a"); base = deterministic_targz(a)
    (tmp_path / "a" / "b.txt").write_text("hellO\n")
    assert deterministic_targz(a) != base
    assert deterministic_targz(a, prefix="x/") != deterministic_targz(a)


def test_targz_has_no_ownership_or_time_metadata(tmp_path):
    data = deterministic_targz(make_src(tmp_path / "a"))
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        for m in t.getmembers():
            assert (m.mtime, m.uid, m.gid, m.uname, m.gname) == (0, 0, 0, "", "")
    assert data[4:8] == bytes(4)               # gzip MTIME = 0


def test_symlink_refused_and_pycache_ignored(tmp_path):
    a = make_src(tmp_path / "a"); base = deterministic_targz(a)
    os.makedirs(tmp_path / "a" / "__pycache__"); (tmp_path / "a" / "__pycache__" / "x.pyc").write_bytes(b"1")
    assert deterministic_targz(a) == base
    os.symlink("/etc/passwd", tmp_path / "a" / "link")
    with pytest.raises(ReproError):
        deterministic_targz(a)


# ---- SBOM ----
def test_sbom_requires_pins():
    for bad in ("fastapi>=0.1", "requests", "x==1.0\ny~=2.0", "-e ."):
        with pytest.raises(SbomError):
            parse_requirements(bad)


def test_sbom_normalizes_and_is_deterministic():
    r = "Uvicorn==0.54.0\nfast_api==1.0  # c\n"
    assert parse_requirements(r) == [("fast-api", "1.0"), ("uvicorn", "0.54.0")]
    assert build_sbom("a", "1", "ab" * 32, r) == build_sbom("a", "1", "ab" * 32, r)


def test_sbom_components():
    s = build_sbom("a", "1", "ab" * 32, "x==1\ny==2")
    assert components(s) == {("x", "1"), ("y", "2")}
    with pytest.raises(SbomError):
        components(b"{}")


def test_targz_order_is_globally_sorted_not_walk_order(tmp_path):
    a = make_src(tmp_path / "a", {"z.txt": "z\n"})
    with tarfile.open(fileobj=io.BytesIO(deterministic_targz(a))) as t:
        names = [m.name for m in t.getmembers()]
    assert names == sorted(names)
