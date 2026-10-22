import datetime as dt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from svid import *
from spire import SpireServer, Agent, AttestationError

TD = "prod.example"
ID_A = f"spiffe://{TD}/ns/kms/coordinator"
NOW = dt.datetime.now(dt.timezone.utc)


def server(ttl=dt.timedelta(minutes=10)):
    return SpireServer(TD, ttl)


@pytest.mark.parametrize("bad", ["http://x/y", "spiffe://", "spiffe://UP.case/x", "spiffe://a/../b", "spiffe://a/./b",
                                 "spiffe://a//b", "spiffe://a/b c", "", "spiffe://a/b?x=1", "spiffe://u@a/b"])
def test_bad_spiffe_ids(bad):
    with pytest.raises(SvidError):
        parse_spiffe_id(bad)


def test_parse_ok():
    assert parse_spiffe_id(ID_A) == (TD, "/ns/kms/coordinator")


def test_issue_and_verify():
    s = server(); k = new_key()
    cert = s.attest(s.create_join_token(ID_A), make_csr(k))
    assert verify_svid(cert, s.bundle(), TD, ID_A) == ID_A
    assert cert.not_valid_after_utc - cert.not_valid_before_utc <= dt.timedelta(minutes=11)


def test_ca_ignores_identity_requested_in_csr():
    """Рабочая нагрузка не может выбрать себе чужой ID, написав его в CSR."""
    s = server(); k = new_key()
    cert = s.attest(s.create_join_token(ID_A), make_csr(k, f"spiffe://{TD}/admin"))
    assert spiffe_id_of(cert) == ID_A


def test_join_token_single_use():
    s = server(); tok = s.create_join_token(ID_A)
    s.attest(tok, make_csr(new_key()))
    with pytest.raises(AttestationError):
        s.attest(tok, make_csr(new_key()))


def test_join_token_expiry_and_unknown():
    s = server(); tok = s.create_join_token(ID_A, dt.timedelta(minutes=1), now=NOW)
    with pytest.raises(AttestationError):
        s.attest(tok, make_csr(new_key()), now=NOW + dt.timedelta(minutes=2))
    with pytest.raises(AttestationError):
        s.attest("guess", make_csr(new_key()))


def test_expired_token_is_not_burned_into_a_cert():
    s = server(); tok = s.create_join_token(ID_A, dt.timedelta(minutes=1), now=NOW)
    with pytest.raises(AttestationError):
        s.attest(tok, make_csr(new_key()), now=NOW + dt.timedelta(hours=1))
    assert s.issued == []


def test_token_for_foreign_domain_refused():
    with pytest.raises(SvidError):
        server().create_join_token("spiffe://other.example/x")


def test_csr_with_bad_signature_refused():
    s = server(); good = make_csr(new_key())
    csr = x509.load_pem_x509_csr(good)
    tampered = bytearray(good)
    # портим подпись внутри DER через пересборку: берём CSR другого ключа с подменённым public key нельзя, поэтому флипаем байт
    der = bytearray(csr.public_bytes(serialization.Encoding.DER)); der[-3] ^= 1
    bad = x509.load_der_x509_csr(bytes(der)).public_bytes(serialization.Encoding.PEM)
    with pytest.raises(SvidError, match="CSR"):
        s.attest(s.create_join_token(ID_A), bad)


def test_ttl_limits():
    ca = CertAuthority(TD); csr = make_csr(new_key())
    for ttl in (dt.timedelta(0), dt.timedelta(hours=2), dt.timedelta(seconds=-5)):
        with pytest.raises(SvidError):
            ca.issue(csr, ID_A, ttl)


def test_ca_refuses_foreign_domain():
    with pytest.raises(SvidError):
        CertAuthority(TD).issue(make_csr(new_key()), "spiffe://evil.example/x")


def test_expired_and_not_yet_valid():
    s = server(); cert = s.attest(s.create_join_token(ID_A), make_csr(new_key()))
    with pytest.raises(SvidError):
        verify_svid(cert, s.bundle(), TD, now=NOW + dt.timedelta(hours=1))
    with pytest.raises(SvidError):
        verify_svid(cert, s.bundle(), TD, now=NOW - dt.timedelta(hours=1))


def test_wrong_ca_rejected():
    s, other = server(), server()
    cert = s.attest(s.create_join_token(ID_A), make_csr(new_key()))
    with pytest.raises(SvidError):
        verify_svid(cert, other.bundle(), TD)


def test_same_subject_different_key_ca_rejected():
    """Атакующий делает CA с тем же именем, но другим ключом: проверка подписи обязана отсеять."""
    s = server()
    fake = CertAuthority(TD)
    fake_cert = x509.CertificateBuilder().subject_name(s.cas[0].cert.subject).issuer_name(s.cas[0].cert.subject) \
        .public_key(fake.key.public_key()).serial_number(1).not_valid_before(NOW - dt.timedelta(days=1)) \
        .not_valid_after(NOW + dt.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True) \
        .sign(fake.key, hashes.SHA256())
    fake.cert = fake_cert
    forged = fake.issue(make_csr(new_key()), ID_A)
    assert forged.issuer == s.cas[0].cert.subject
    with pytest.raises(SvidError, match="подпись"):
        verify_svid(forged, s.bundle(), TD)


def test_expected_id_mismatch():
    s = server(); cert = s.attest(s.create_join_token(ID_A), make_csr(new_key()))
    with pytest.raises(SvidError):
        verify_svid(cert, s.bundle(), TD, f"spiffe://{TD}/other")


def test_leaf_must_not_be_ca():
    s = server()
    with pytest.raises(SvidError):                       # сам CA-сертификат не является SVID
        verify_svid(s.cas[0].cert, s.bundle(), TD)


def test_agent_rotation_new_key_same_identity():
    s = server(); a = Agent(s, s.create_join_token(ID_A), now=NOW)
    old_key, old_cert = a.key, a.cert
    assert not a.rotate_if_needed(NOW + dt.timedelta(minutes=1))
    assert a.rotate_if_needed(NOW + dt.timedelta(minutes=6))
    assert a.cert.serial_number != old_cert.serial_number
    assert a.cert.public_key().public_numbers() != old_cert.public_key().public_numbers()
    assert spiffe_id_of(a.cert) == ID_A


def test_renew_with_expired_svid_refused():
    s = server(); a = Agent(s, s.create_join_token(ID_A), now=NOW)
    with pytest.raises(AttestationError):
        s.renew(a.cert, make_csr(new_key()), now=NOW + dt.timedelta(hours=1))


def test_renew_with_foreign_svid_refused():
    s, evil = server(), server()
    a = Agent(evil, evil.create_join_token(ID_A), now=NOW)
    with pytest.raises(AttestationError):
        s.renew(a.cert, make_csr(new_key()))


def test_renew_identity_comes_from_current_svid_not_csr():
    s = server(); a = Agent(s, s.create_join_token(ID_A))
    c = s.renew(a.cert, make_csr(new_key(), f"spiffe://{TD}/admin"))
    assert spiffe_id_of(c) == ID_A


def test_ca_rotation_overlap_and_retire():
    s = server(); a = Agent(s, s.create_join_token(ID_A))
    old_bundle = s.bundle()
    s.rotate_ca()
    new_cert = s.renew(a.cert, make_csr(new_key()))               # выпущен новым CA
    assert verify_svid(new_cert, s.bundle(), TD) == ID_A          # в новом bundle принимаются оба
    assert verify_svid(a.cert, s.bundle(), TD) == ID_A            # старые SVID ещё работают (перекрытие)
    with pytest.raises(SvidError):                                # у отставших клиентов старый bundle не знает новый CA
        verify_svid(new_cert, old_bundle, TD)
    s.retire_old_cas()
    with pytest.raises(SvidError):                                # после вывода старого CA его SVID не принимаются
        verify_svid(a.cert, s.bundle(), TD)
    assert verify_svid(new_cert, s.bundle(), TD) == ID_A


def test_issued_log_records_every_svid():
    s = server(); a = Agent(s, s.create_join_token(ID_A)); a.rotate_if_needed(NOW + dt.timedelta(minutes=9))
    assert [i for i, _ in s.issued] == [ID_A, ID_A]


def _build(ca, sans, is_ca=False, not_after=None):
    k = new_key()
    b = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(ca.cert.subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(NOW - dt.timedelta(minutes=1))
         .not_valid_after(not_after or NOW + dt.timedelta(minutes=5))
         .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), True))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in sans]), True)
    return b.sign(ca.key, hashes.SHA256())


def test_subordinate_ca_with_spiffe_san_rejected_as_leaf():
    s = server(); c = _build(s.cas[0], [ID_A], is_ca=True)
    with pytest.raises(SvidError, match="CA"):
        verify_svid(c, s.bundle(), TD)


def test_cert_of_foreign_domain_signed_by_trusted_ca_rejected():
    s = server(); c = _build(s.cas[0], [f"spiffe://evil.example/x"])
    with pytest.raises(SvidError, match="trust domain"):
        verify_svid(c, s.bundle(), TD)


def test_multiple_uri_sans_rejected():
    s = server(); c = _build(s.cas[0], [ID_A, f"spiffe://{TD}/admin"])
    with pytest.raises(SvidError, match="ровно один"):
        verify_svid(c, s.bundle(), TD)


def test_no_san_rejected():
    s = server()
    with pytest.raises(SvidError):
        verify_svid(_build(s.cas[0], []), s.bundle(), TD)


def test_expired_ca_in_bundle_not_trusted():
    s = server()
    c = _build(s.cas[0], [ID_A], not_after=NOW + dt.timedelta(days=60))     # лист живёт дольше CA
    later = s.cas[0].cert.not_valid_after_utc + dt.timedelta(seconds=1)
    assert verify_svid(c, s.bundle(), TD, now=later - dt.timedelta(seconds=5)) == ID_A
    with pytest.raises(SvidError):
        verify_svid(c, s.bundle(), TD, now=later)
