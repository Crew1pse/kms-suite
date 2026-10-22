import dataclasses, pytest
from helpers import *
from pqxdh import *
from e2ee import Ratchet, _dh, _gen, _hkdf
from kyber_py.ml_kem import ML_KEM_768


def setup(one_time_pq=False, with_opk=True):
    bob, alice = IdentityKeyPair(), IdentityKeyPair()
    s, pq = PrekeyStore(bob), PQPrekeyStore(bob)
    oid, opk = (s.new_opks(1)[0]) if with_opk else (None, None)
    pid, pek, psig = pq.new_key(one_time_pq)
    base = PrekeyBundle(bob.public, s.spk_id, s.spk, s.spk_sig, oid, opk)
    return alice, bob, s, pq, PQBundle(base, pid, pek, psig, one_time_pq)


@pytest.mark.parametrize("ot", [False, True])
@pytest.mark.parametrize("opk", [False, True])
def test_agreement_and_ratchet_works(ot, opk):
    alice, bob, s, pq, b = setup(ot, opk)
    sk, ad, h = pqxdh_initiate(alice, b)
    sk2, ad2 = pqxdh_respond(s, pq, h)
    assert sk == sk2 and ad == ad2
    a, bb = Ratchet.init_alice(sk, s.spk, ad), Ratchet.init_bob(sk2, s.spk_priv, s.spk, ad2)
    assert bb.decrypt(*a.encrypt(b"post-quantum hello")) == b"post-quantum hello"
    assert a.decrypt(*bb.encrypt(b"reply")) == b"reply"


def test_hybrid_quantum_attacker_who_breaks_x25519_still_blind():
    """Атакующий знает ВСЕ DH-секреты (сломал X25519), но не ss ML-KEM: ключа получить не может."""
    alice, bob, s, pq, b = setup()
    sk, _, h = pqxdh_initiate(alice, b)
    dh = [_dh(s.spk_priv, alice.public.dh), _dh(bob.dh_priv, h.base.ek), _dh(s.spk_priv, h.base.ek)]
    guess_ss = ML_KEM_768.encaps(b.pq_ek)[0]                 # любой другой ss
    from pqxdh import _kdf
    opk_part = []
    assert _kdf(dh + opk_part, guess_ss) != sk


def test_hybrid_classical_attacker_with_kem_secret_but_no_dh_blind():
    alice, bob, s, pq, b = setup(with_opk=False)
    sk, _, h = pqxdh_initiate(alice, b)
    ss = ML_KEM_768.decaps(pq._keys[b.pq_id][0], h.pq_ct)    # ss известен
    from pqxdh import _kdf
    wrong_dh = [_dh(_gen()[0], _gen()[1]) for _ in range(3)]
    assert _kdf(wrong_dh, ss) != sk


def test_kdf_depends_on_pq_part_changing_ct_changes_key():
    alice, bob, s, pq, b = setup()
    sk, _, h = pqxdh_initiate(alice, b)
    bad_ct = bytes([h.pq_ct[0] ^ 1]) + h.pq_ct[1:]
    sk2, _ = pqxdh_respond(s, pq, dataclasses.replace(h, pq_ct=bad_ct))       # неявный отказ ML-KEM: другой ключ
    assert sk2 != sk
    a, bb = Ratchet.init_alice(sk, s.spk, b""), Ratchet.init_bob(sk2, s.spk_priv, s.spk, b"")
    with pytest.raises(DecryptionError):
        bb.decrypt(*a.encrypt(b"x"))


def test_pq_signature_must_verify_and_is_bound():
    alice, bob, s, pq, b = setup()
    mallory = IdentityKeyPair(); mpq = PQPrekeyStore(mallory); mid, mek, msig = mpq.new_key(False)
    with pytest.raises(E2EEError, match="PQ"):      # ML-KEM ключ Мэллори под подписью Мэллори, но ключ идентичности Боба
        pqxdh_initiate(alice, dataclasses.replace(b, pq_id=mid, pq_ek=mek, pq_sig=msig))
    with pytest.raises(E2EEError, match="PQ"):      # подмена только ключа, подпись настоящая
        pqxdh_initiate(alice, dataclasses.replace(b, pq_ek=mek))
    with pytest.raises(E2EEError, match="PQ"):      # роль ключа (one-time vs last-resort) в подписи
        pqxdh_initiate(alice, dataclasses.replace(b, pq_one_time=True))


def test_classical_signature_still_checked():
    alice, bob, s, pq, b = setup()
    evil = PrekeyStore(IdentityKeyPair())
    with pytest.raises(E2EEError, match="signed prekey"):
        pqxdh_initiate(alice, dataclasses.replace(b, base=dataclasses.replace(b.base, spk=evil.spk)))


def test_one_time_pq_key_single_use_last_resort_reusable():
    for ot, second_ok in ((True, False), (False, True)):
        alice, bob, s, pq, b = setup(ot, with_opk=False)
        _, _, h = pqxdh_initiate(alice, b)
        pqxdh_respond(s, pq, h)
        if second_ok:
            pqxdh_respond(s, pq, h)
        else:
            with pytest.raises(E2EEError):
                pqxdh_respond(s, pq, h)


def test_malformed_lengths_rejected():
    alice, bob, s, pq, b = setup()
    with pytest.raises(E2EEError):
        pqxdh_initiate(alice, dataclasses.replace(b, pq_ek=b.pq_ek[:-1]))
    _, _, h = pqxdh_initiate(alice, b)
    with pytest.raises(E2EEError):
        pqxdh_respond(s, pq, dataclasses.replace(h, pq_ct=h.pq_ct[:-1]))
    with pytest.raises(E2EEError):
        pqxdh_respond(s, pq, dataclasses.replace(h, pq_id=1))


def test_sessions_independent():
    alice, bob, s, pq, b = setup(with_opk=False)
    assert pqxdh_initiate(alice, b)[0] != pqxdh_initiate(alice, b)[0]


def test_pq_signature_binds_identity_dh_key():
    alice, bob, s, pq, b = setup()
    mallory = IdentityKeyPair()
    spliced = dataclasses.replace(b.base, identity=IdentityPublic(mallory.public.dh, bob.public.sig))
    with pytest.raises(E2EEError):
        pqxdh_initiate(alice, dataclasses.replace(b, base=spliced))


def test_validly_signed_but_wrong_length_kem_key_rejected():
    alice, bob, s, pq, b = setup()
    short = b.pq_ek[:-5]
    sig = bob.sign(b"PQXDH-KEM-v1" + b"LR" + bob.public.dh + short)
    with pytest.raises(E2EEError, match="длина"):
        pqxdh_initiate(alice, dataclasses.replace(b, pq_ek=short, pq_sig=sig))
