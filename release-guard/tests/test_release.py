import copy, dataclasses, json, base64
import pytest
from helpers import *
import frost, dkg
from dsse import sign_envelope


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def test_happy_path(w):
    art, b = w.release()
    st = verify_release(art, b, w.policy, rebuild_src=w.src)
    assert st["subject"][0]["name"] == "app-1.0.tar.gz"


def test_modified_artifact_rejected(w):
    art, b = w.release()
    with pytest.raises(ReleaseRejected, match="хэш артефакта"):
        verify_release(art + b"x", b, w.policy)


def test_sbom_swap_rejected(w):
    art, b = w.release()
    bad = dataclasses.replace(b, sbom=b.sbom.replace(b"fastapi", b"fastxpi"))
    with pytest.raises(ReleaseRejected, match="SBOM"):
        verify_release(art, bad, w.policy)


def test_untrusted_signer_rejected(w):
    art, b = w.release(signers=[("k1", Ed25519PrivateKey.generate().sign)])   # подпись не тем ключом
    with pytest.raises(ReleaseRejected, match="подпись"):
        verify_release(art, b, w.policy)


def test_threshold_policy_two_of_two(w):
    w.policy.threshold = 2
    art, one = w.release()
    with pytest.raises(ReleaseRejected, match="подпись"):
        verify_release(art, one, w.policy)
    art, two = w.release(signers=[("k1", w.k1.sign), ("k2", w.k2.sign)])
    verify_release(art, two, w.policy)


def test_blocked_component(w):
    art, b = w.release()
    w.policy.blocked_components = {("fastapi", "0.143.3")}
    with pytest.raises(ReleaseRejected, match="запрещённые"):
        verify_release(art, b, w.policy)


def test_untrusted_builder(w):
    art, b = w.release()
    w.policy.allowed_builders = {"https://other"}
    with pytest.raises(ReleaseRejected, match="builder"):
        verify_release(art, b, w.policy)


def test_envelope_not_in_log_rejected(w):
    """Подписано правильно, но в журнал не записано (или записано другое) - релиз отвергается."""
    art, b = w.release()
    other = copy.deepcopy(b.envelope)
    other["signatures"] = [{"keyid": "k1", "sig": other["signatures"][0]["sig"]}, *other["signatures"]]  # другой конверт, та же подпись
    with pytest.raises(ReleaseRejected, match="включения"):
        verify_release(art, dataclasses.replace(b, envelope=other), w.policy)


def test_log_proof_tamper_and_wrong_index(w):
    art, b = w.release(); w.release(version="1.1"); art3, b3 = w.release(version="1.2")
    for mut in (lambda l: l.update(index=l["index"] + 1),
                lambda l: l.update(proof=l["proof"][:-1]),
                lambda l: l["proof"].__setitem__(0, "00" * 32)):
        log = copy.deepcopy(b3.log); mut(log)
        with pytest.raises(ReleaseRejected):
            verify_release(art3, dataclasses.replace(b3, log=log), w.policy)


def test_forged_sth_rejected(w):
    art, b = w.release()
    log = copy.deepcopy(b.log); log["sth"]["root_hash"] = "11" * 32
    with pytest.raises(ReleaseRejected, match="STH"):
        verify_release(art, dataclasses.replace(b, log=log), w.policy)
    evil = Ed25519PrivateKey.generate()
    w.policy.tlog_public_key = raw(evil)
    with pytest.raises(ReleaseRejected, match="STH"):
        verify_release(art, b, w.policy)


def test_old_sth_rollback(w):
    art, b = w.release()
    w.policy.min_log_size = b.log["sth"]["tree_size"] + 1
    with pytest.raises(ReleaseRejected, match="откат"):
        verify_release(art, b, w.policy)


def test_old_release_still_verifies_after_log_grows(w):
    art, b = w.release()
    for v in ("1.1", "1.2", "1.3"):
        w.release(version=v)
    verify_release(art, b, w.policy)        # доказательство привязано к своему STH


def test_source_tampered_after_signing_detected_by_rebuild(w, tmp_path):
    art, b = w.release()
    (tmp_path / "src" / "pkg" / "a.py").write_text("print('backdoor')\n")
    with pytest.raises(ReleaseRejected, match="пересборка"):
        verify_release(art, b, w.policy, rebuild_src=w.src)


def test_signed_payload_wrong_type_rejected(w):
    art, b = w.release()
    env = sign_envelope(base64.b64decode(b.envelope["payload"]), "text/plain", w.signers)
    with pytest.raises(ReleaseRejected):
        verify_release(art, dataclasses.replace(b, envelope=env), w.policy)


def test_garbage_payload(w):
    art, b = w.release()
    env = sign_envelope(b"not json", "application/vnd.in-toto+json", w.signers)
    with pytest.raises(ReleaseRejected, match="provenance"):
        verify_release(art, dataclasses.replace(b, envelope=env), w.policy)


def test_wrong_predicate_type(w):
    art, b = w.release()
    st = json.loads(base64.b64decode(b.envelope["payload"])); st["predicateType"] = "evil"
    env = sign_envelope(json.dumps(st).encode(), "application/vnd.in-toto+json", w.signers)
    with pytest.raises(ReleaseRejected):
        verify_release(art, dataclasses.replace(b, envelope=env), w.policy)


def test_threshold_frost_signature_as_release_signer(w):
    """Релиз подписан 3-из-5 пороговой подписью FROST, а проверяется обычным Ed25519 - ключ группы."""
    pkg, shares = frost.trusted_dealer_keygen(5, 3)

    def threshold_sign(msg):
        signers = {i: frost.Signer(shares[i]) for i in (1, 3, 5)}
        com = [s.commit() for s in signers.values()]
        return frost.aggregate(pkg, msg, com, [s.sign(msg, com) for s in signers.values()])

    w.policy.trusted_keys["frost-group"] = pkg.group_public_key
    art, b = w.release(signers=[("frost-group", threshold_sign)])
    verify_release(art, b, w.policy, rebuild_src=w.src)


def test_wrong_predicate_type_even_if_logged(w):
    """Конверт подписан и записан в журнал, но тип predicate чужой: отвергаем по самому типу."""
    art, b = w.release()
    st = json.loads(base64.b64decode(b.envelope["payload"])); st["predicateType"] = "evil"
    env = sign_envelope(json.dumps(st).encode(), "application/vnd.in-toto+json", w.signers)
    idx, sth = w.log.append(log_entry(st["subject"][0]["digest"]["sha256"], env))
    log = {"index": idx, "sth": sth, "proof": [p.hex() for p in w.log.inclusion_proof(idx, sth["tree_size"])]}
    with pytest.raises(ReleaseRejected, match="тип statement"):
        verify_release(art, Bundle(env, b.sbom, log), w.policy)


# ---------- постквантовые подписи ----------
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey


def _pq_world(w):
    pq = MLDSA65PrivateKey.generate()
    w.policy.trusted_keys["pq1"] = ("ml-dsa-65", pq.public_key().public_bytes_raw())
    return pq


def test_mldsa_release_roundtrip(w):
    pq = _pq_world(w)
    art, b = w.release(signers=[("pq1", pq.sign)])
    verify_release(art, b, w.policy, rebuild_src=w.src)


def test_mldsa_tamper_rejected(w):
    pq = _pq_world(w)
    art, b = w.release(signers=[("pq1", pq.sign)])
    sig = bytearray(base64.b64decode(b.envelope["signatures"][0]["sig"])); sig[10] ^= 1
    env = copy.deepcopy(b.envelope); env["signatures"][0]["sig"] = base64.b64encode(bytes(sig)).decode()
    with pytest.raises(ReleaseRejected, match="подпись"):
        verify_release(art, dataclasses.replace(b, envelope=env), w.policy)


def test_hybrid_policy_requires_both_algorithms(w):
    pq = _pq_world(w)
    w.policy.require_algs = ("ed25519", "ml-dsa-65"); w.policy.threshold = 1
    art, only_classic = w.release()
    with pytest.raises(ReleaseRejected, match="ml-dsa-65"):
        verify_release(art, only_classic, w.policy)
    art, only_pq = w.release(signers=[("pq1", pq.sign)])
    with pytest.raises(ReleaseRejected, match="ed25519"):
        verify_release(art, only_pq, w.policy)
    art, both = w.release(signers=[("k1", w.k1.sign), ("pq1", pq.sign)])
    verify_release(art, both, w.policy, rebuild_src=w.src)


def test_hybrid_survives_when_one_scheme_is_broken(w):
    """«Сломали» Ed25519 (подписывает кто угодно под ключом k1): без валидной ML-DSA подписи релиз не принят."""
    pq = _pq_world(w)
    w.policy.require_algs = ("ed25519", "ml-dsa-65")
    forger = Ed25519PrivateKey.generate()
    w.policy.trusted_keys["k1"] = raw(forger)             # модель: атакующий владеет секретом k1
    art, b = w.release(signers=[("k1", forger.sign)])
    with pytest.raises(ReleaseRejected):
        verify_release(art, b, w.policy)


def test_unknown_algorithm_and_wrong_key_type(w):
    w.policy.trusted_keys["weird"] = ("rsa", b"x")
    art, b = w.release(signers=[("weird", lambda m: b"x" * 64)])
    with pytest.raises(ReleaseRejected):
        verify_release(art, b, w.policy)
    pq = MLDSA65PrivateKey.generate()
    w.policy.trusted_keys["pq1"] = ("ml-dsa-65", b"short")
    art, b = w.release(signers=[("pq1", pq.sign)])
    with pytest.raises(ReleaseRejected):
        verify_release(art, b, w.policy)


def test_pq_signature_sizes_documented(w):
    pq = _pq_world(w)
    art, b = w.release(signers=[("k1", w.k1.sign), ("pq1", pq.sign)])
    sizes = {s["keyid"]: len(base64.b64decode(s["sig"])) for s in b.envelope["signatures"]}
    assert sizes == {"k1": 64, "pq1": 3309}
