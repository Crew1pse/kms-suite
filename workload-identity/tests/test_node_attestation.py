import datetime as dt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from softtpm import *
from node_attest import *
from spire import SpireServer, AttestationError
from svid import make_csr, new_key, verify_svid, spiffe_id_of

TD = "prod.example"
GOOD = [(0, b"firmware-v1"), (1, b"bootloader-v1"), (4, b"kernel-5.15-signed"), (7, b"secureboot-on")]
SEL = (0, 1, 4, 7)
D = lambda b: sha(b)
POLICY = BootPolicy(SEL, {0: {D(b"firmware-v1")}, 1: {D(b"bootloader-v1")}, 4: {D(b"kernel-5.15-signed")}, 7: {D(b"secureboot-on")}})


def boot(tpm, events=GOOD):
    for p, d in events:
        tpm.measure(p, d)
    return tpm


@pytest.fixture
def env():
    vendor = Manufacturer()
    srv = SpireServer(TD)
    att = NodeAttestor(srv, [vendor.cert], POLICY)
    return vendor, srv, att


def test_happy_path_issues_node_svid_bound_to_ek(env):
    vendor, srv, att = env
    tpm = boot(SoftTPM(vendor)); key = new_key()
    cert = attest_node(tpm, att, make_csr(key))
    sid = verify_svid(cert, srv.bundle(), TD)
    assert sid == att.node_spiffe_id(att.ek_hash(tpm.ek_cert))
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()


def test_identity_is_stable_per_tpm_and_distinct_between_tpms(env):
    vendor, srv, att = env
    a, b = boot(SoftTPM(vendor)), boot(SoftTPM(vendor))
    ida = spiffe_id_of(attest_node(a, att, make_csr(new_key())))
    ida2 = spiffe_id_of(attest_node(a, att, make_csr(new_key())))
    idb = spiffe_id_of(attest_node(b, att, make_csr(new_key())))
    assert ida == ida2 != idb


def test_ca_ignores_csr_requested_identity(env):
    vendor, srv, att = env
    cert = attest_node(boot(SoftTPM(vendor)), att, make_csr(new_key(), f"spiffe://{TD}/admin"))
    assert spiffe_id_of(cert).startswith(f"spiffe://{TD}/node/")


# ---- кто угодно, но не настоящий TPM ----
def test_software_impersonator_without_vendor_cert_rejected(env):
    _, srv, att = env
    fake = boot(SoftTPM(Manufacturer("Evil Vendor")))
    with pytest.raises(AttestationError, match="производител"):
        attest_node(fake, att, make_csr(new_key()))


def test_stolen_ek_certificate_without_ek_private_key_fails_activation(env):
    """Атакующий копирует публичный EK-сертификат чужого TPM, но закрытого EK у него нет."""
    vendor, srv, att = env
    victim = boot(SoftTPM(vendor)); attacker = boot(SoftTPM(vendor))
    attacker.ek_cert = victim.ek_cert                         # подмена сертификата
    with pytest.raises(TpmError):
        attest_node(attacker, att, make_csr(new_key()))


def test_ak_not_resident_in_ek_tpm_cannot_activate(env):
    """AK создан где-то снаружи (в софте), а EK настоящий: credential не расшифровать."""
    vendor, srv, att = env
    tpm = boot(SoftTPM(vendor))
    soft_ak = ec.generate_private_key(ec.SECP256R1()); der = pub_der(soft_ak.public_key()); name = sha(der)
    csr = make_csr(new_key())
    ch = att.begin(tpm.ek_cert, der, csr)
    with pytest.raises(TpmError):
        tpm.activate_credential(name, ch.credential)


def test_credential_for_other_ak_name_rejected_by_tpm(env):
    vendor, srv, att = env
    tpm = boot(SoftTPM(vendor)); der1, n1 = tpm.create_ak(); der2, n2 = tpm.create_ak()
    ch = att.begin(tpm.ek_cert, der1, make_csr(new_key()))
    with pytest.raises(TpmError):
        tpm.activate_credential(n2, ch.credential)           # привязка к имени AK


# ---- нарушения протокола ----
def prepared(env, tpm=None, csr=None, events=None):
    vendor, srv, att = env
    tpm = tpm or boot(SoftTPM(vendor))
    csr = csr or make_csr(new_key())
    der, name = tpm.create_ak()
    ch = att.begin(tpm.ek_cert, der, csr)
    secret = tpm.activate_credential(name, ch.credential)
    csr_der = x509.load_pem_x509_csr(csr).public_bytes(serialization.Encoding.DER)
    q, sig = tpm.quote(name, sha(ch.nonce + csr_der), SEL)
    return att, tpm, ch, secret, q, sig


def test_session_is_single_use(env):
    att, tpm, ch, secret, q, sig = prepared(env)
    att.complete(ch.session_id, secret, q, sig, tpm.event_log)
    with pytest.raises(AttestationError, match="использована"):
        att.complete(ch.session_id, secret, q, sig, tpm.event_log)


def test_failed_attempt_also_burns_session(env):
    att, tpm, ch, secret, q, sig = prepared(env)
    with pytest.raises(AttestationError):
        att.complete(ch.session_id, b"x" * 32, q, sig, tpm.event_log)
    with pytest.raises(AttestationError, match="использована"):
        att.complete(ch.session_id, secret, q, sig, tpm.event_log)


def test_session_expiry(env):
    att, tpm, ch, secret, q, sig = prepared(env)
    with pytest.raises(AttestationError, match="просрочена"):
        att.complete(ch.session_id, secret, q, sig, tpm.event_log, now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))


def test_replayed_quote_from_old_session_rejected(env):
    att, tpm, ch1, s1, q1, sig1 = prepared(env)
    att.complete(ch1.session_id, s1, q1, sig1, tpm.event_log)
    vendor, srv, att2 = env
    der, name = tpm.create_ak(); ch2 = att.begin(tpm.ek_cert, der, make_csr(new_key()))
    s2 = tpm.activate_credential(name, ch2.credential)
    with pytest.raises(AttestationError, match="quote"):
        att.complete(ch2.session_id, s2, q1, sig1, tpm.event_log)       # старый quote под новый nonce


def test_csr_swap_after_quote_rejected(env):
    """Quote подписан над хэшем конкретного CSR: подменить ключ после аттестации нельзя."""
    vendor, srv, att = env
    tpm = boot(SoftTPM(vendor)); good_csr = make_csr(new_key()); evil_csr = make_csr(new_key())
    der, name = tpm.create_ak()
    ch = att.begin(tpm.ek_cert, der, evil_csr)                # сервер видит CSR злоумышленника
    secret = tpm.activate_credential(name, ch.credential)
    good_der = x509.load_pem_x509_csr(good_csr).public_bytes(serialization.Encoding.DER)
    q, sig = tpm.quote(name, sha(ch.nonce + good_der), SEL)   # а quote был сделан под другой CSR
    with pytest.raises(AttestationError, match="quote"):
        att.complete(ch.session_id, secret, q, sig, tpm.event_log)


def test_quote_signed_by_other_key_rejected(env):
    att, tpm, ch, secret, q, sig = prepared(env)
    other = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives import hashes
    with pytest.raises(AttestationError, match="подпись"):
        att.complete(ch.session_id, secret, q, other.sign(q, ec.ECDSA(hashes.SHA256())), tpm.event_log)


def test_quote_over_fewer_pcrs_rejected(env):
    """Узел отдаёт quote только по PCR0 (скрывая ядро): политика выбора PCR жёсткая."""
    vendor, srv, att = env
    tpm = boot(SoftTPM(vendor)); csr = make_csr(new_key())
    der, name = tpm.create_ak(); ch = att.begin(tpm.ek_cert, der, csr)
    secret = tpm.activate_credential(name, ch.credential)
    csr_der = x509.load_pem_x509_csr(csr).public_bytes(serialization.Encoding.DER)
    q, sig = tpm.quote(name, sha(ch.nonce + csr_der), (0,))
    with pytest.raises(AttestationError, match="quote"):
        att.complete(ch.session_id, secret, q, sig, tpm.event_log)


# ---- состояние загрузки ----
def test_tampered_kernel_rejected(env):
    vendor, *_ = env
    evil = boot(SoftTPM(vendor), [(0, b"firmware-v1"), (1, b"bootloader-v1"), (4, b"kernel-rootkit"), (7, b"secureboot-on")])
    with pytest.raises(AttestationError, match="измерение"):
        attest_node(evil, env[2], make_csr(new_key()))


def test_forged_event_log_not_matching_real_pcr_rejected(env):
    """Узел с руткитом показывает чистый event log, но TPM реально измерил другое: quote не сходится с проигрыванием лога."""
    vendor, srv, att = env
    evil = boot(SoftTPM(vendor), [(0, b"firmware-v1"), (1, b"bootloader-v1"), (4, b"kernel-rootkit"), (7, b"secureboot-on")])
    clean_log = list(GOOD)
    der, name = evil.create_ak(); csr = make_csr(new_key())
    ch = att.begin(evil.ek_cert, der, csr); secret = evil.activate_credential(name, ch.credential)
    csr_der = x509.load_pem_x509_csr(csr).public_bytes(serialization.Encoding.DER)
    q, sig = evil.quote(name, sha(ch.nonce + csr_der), SEL)
    with pytest.raises(AttestationError, match="quote"):
        att.complete(ch.session_id, secret, q, sig, clean_log)


def test_extra_measurement_after_boot_changes_pcr_and_is_caught(env):
    vendor, *_ = env
    t = boot(SoftTPM(vendor)); t.measure(4, b"unexpected-module")
    with pytest.raises(AttestationError):
        attest_node(t, env[2], make_csr(new_key()))


def test_event_in_unpolicied_selected_pcr_rejected(env):
    vendor, srv, att = env
    att.policy = BootPolicy(SEL, {0: POLICY.allowed_events[0]})              # у остальных PCR политики нет
    with pytest.raises(AttestationError, match="политики"):
        attest_node(boot(SoftTPM(vendor)), att, make_csr(new_key()))


def test_golden_digest_policy(env):
    vendor, srv, att = env
    t = boot(SoftTPM(vendor))
    att.policy = BootPolicy(SEL, POLICY.allowed_events, {pcr_digest(t.pcrs, SEL)})
    attest_node(t, att, make_csr(new_key()))
    att.policy = BootPolicy(SEL, POLICY.allowed_events, {bytes(32)})
    with pytest.raises(AttestationError, match="эталон"):
        attest_node(boot(SoftTPM(vendor)), att, make_csr(new_key()))


def test_pcr_index_out_of_range_in_log(env):
    att, tpm, ch, secret, q, sig = prepared(env)
    with pytest.raises(AttestationError, match="PCR"):
        att.complete(ch.session_id, secret, q, sig, tpm.event_log + [(99, b"x")])


def test_revoked_ek_denied(env):
    vendor, srv, att = env
    t = boot(SoftTPM(vendor)); att.denylist.add(att.ek_hash(t.ek_cert))
    with pytest.raises(AttestationError, match="отозван"):
        attest_node(t, att, make_csr(new_key()))


def test_expired_ek_cert_rejected(env):
    vendor, srv, att = env
    t = boot(SoftTPM(vendor))
    with pytest.raises(AttestationError, match="срока"):
        att.begin(t.ek_cert, t.create_ak()[0], make_csr(new_key()), now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=4000))


def test_pcr_extend_is_order_dependent_and_not_resettable():
    v = Manufacturer(); a, b = SoftTPM(v), SoftTPM(v)
    a.measure(0, b"x"); a.measure(0, b"y"); b.measure(0, b"y"); b.measure(0, b"x")
    assert a.pcrs[0] != b.pcrs[0]
    assert not hasattr(a, "reset_pcr")


def test_attested_svid_works_for_renewal_and_rotation(env):
    """Дальше узел живёт как обычный агент: продление по действующему SVID (без нового TPM-раунда)."""
    from datetime import timedelta
    vendor, srv, att = env
    key = new_key(); cert = attest_node(boot(SoftTPM(vendor)), att, make_csr(key))
    renewed = srv.renew(cert, make_csr(new_key()))
    assert spiffe_id_of(renewed) == spiffe_id_of(cert)


def test_csr_without_proof_of_possession_rejected(env):
    vendor, srv, att = env
    t = boot(SoftTPM(vendor))
    der = bytearray(x509.load_pem_x509_csr(make_csr(new_key())).public_bytes(serialization.Encoding.DER)); der[-4] ^= 1
    bad = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(AttestationError, match="CSR"):
        att.begin(t.ek_cert, t.create_ak()[0], bad)


def test_pcr_extend_known_answer():
    """PCR_new = SHA256(PCR_old || SHA256(data)) - порядок конкатенации фиксирован спецификацией TPM."""
    import hashlib
    old = bytes(32)
    assert extend(old, b"abc") == hashlib.sha256(old + hashlib.sha256(b"abc").digest()).digest()
    assert extend(old, b"abc") != hashlib.sha256(hashlib.sha256(b"abc").digest() + old).digest()
