import dataclasses, pytest
from helpers import *
from relay import decode_envelope, encode_envelope


def test_x3dh_with_and_without_opk_agree():
    for with_opk in (True, False):
        bob, alice = IdentityKeyPair(), IdentityKeyPair()
        s = PrekeyStore(bob)
        oid, opk = (s.new_opks(1)[0]) if with_opk else (None, None)
        sk, ad, init = x3dh_initiate(alice, PrekeyBundle(bob.public, s.spk_id, s.spk, s.spk_sig, oid, opk))
        assert x3dh_respond(s, init)[0] == sk


def test_forged_spk_signature_rejected():
    bob, mallory, alice = IdentityKeyPair(), IdentityKeyPair(), IdentityKeyPair()
    s, evil = PrekeyStore(bob), PrekeyStore(mallory)
    with pytest.raises(E2EEError):   # подпись Мэллори, ключ идентичности Боба
        x3dh_initiate(alice, PrekeyBundle(bob.public, 1, evil.spk, evil.spk_sig))
    with pytest.raises(E2EEError):   # SPK подменён, подпись настоящая
        x3dh_initiate(alice, PrekeyBundle(bob.public, 1, evil.spk, s.spk_sig))
    with pytest.raises(E2EEError):   # подпись Боба над его prekey, но под чужим ключом идентичности
        x3dh_initiate(alice, PrekeyBundle(mallory.public, 1, s.spk, s.spk_sig))


def test_opk_is_single_use():
    bob, alice = IdentityKeyPair(), IdentityKeyPair()
    s = PrekeyStore(bob); oid, opk = s.new_opks(1)[0]
    _, _, init = x3dh_initiate(alice, PrekeyBundle(bob.public, 1, s.spk, s.spk_sig, oid, opk))
    x3dh_respond(s, init)
    with pytest.raises(E2EEError):
        x3dh_respond(s, init)


def test_sessions_have_distinct_keys():
    bob = IdentityKeyPair(); s = PrekeyStore(bob)
    keys = {x3dh_initiate(IdentityKeyPair(), PrekeyBundle(bob.public, 1, s.spk, s.spk_sig))[0] for _ in range(5)}
    assert len(keys) == 5


def test_low_order_point_rejected():
    with pytest.raises(E2EEError):
        from e2ee import _dh, _gen
        _dh(_gen()[0], bytes(32))


def test_end_to_end_via_relay_and_relay_sees_only_ciphertext():
    relay, a, b = make_pair()
    a.send("bob", b"hello bob top secret")
    assert b.receive_all() == [("alice", b"hello bob top secret")]
    b.send("alice", b"hi alice")
    assert a.receive_all() == [("bob", b"hi alice")]
    for i in range(10):
        a.send("bob", b"m%d" % i); b.receive_all()
    blob = b"".join(relay.seen)
    assert b"top secret" not in blob and b"hi alice" not in blob


def test_init_header_dropped_after_reply():
    relay, a, b = make_pair()
    a.send("bob", b"1"); a.send("bob", b"2")       # оба несут init (Боб мог получить только второе)
    assert all(decode_envelope(e)[1] is not None for e in relay.seen)
    b.receive_all(); b.send("alice", b"r"); a.receive_all()
    a.send("bob", b"3")
    assert decode_envelope(relay.seen[-1])[1] is None


def test_first_message_lost_second_still_works():
    relay, a, b = make_pair()
    a.send("bob", b"1"); a.send("bob", b"2")
    relay._queues["bob"].pop(0)                      # relay потерял первое
    assert b.receive_all() == [("alice", b"2")]


def test_opk_exhaustion_falls_back_to_no_opk():
    relay, a, b = make_pair()
    b.publish_prekeys(0)
    a.send("bob", b"x"); assert b.receive_all() == [("alice", b"x")]


def test_tofu_detects_identity_change():
    relay, a, b = make_pair()
    a.send("bob", b"x"); b.receive_all()
    # "Боб" переустановился - новые ключи под тем же именем (или MITM на relay)
    evil = Client("bob", relay); evil.publish_prekeys()
    a.sessions.clear()
    with pytest.raises(IdentityChanged):
        a.send("bob", b"y")


def test_relay_mitm_substituting_bundle_is_detected_by_safety_number():
    relay, a, b = make_pair()
    mitm = Client("bob", relay); mitm.publish_prekeys()      # relay отдаёт ключи MITM
    a.send("bob", b"hi")
    assert safety_number(a.identity.public, mitm.identity.public) != safety_number(a.identity.public, b.identity.public)


def test_safety_number_symmetric_and_stable():
    x, y = IdentityKeyPair().public, IdentityKeyPair().public
    assert safety_number(x, y) == safety_number(y, x)
    assert len(safety_number(x, y).split()) == 12


def test_corrupted_envelopes_are_recorded_not_crash():
    relay, a, b = make_pair()
    relay.post("bob", b"not json"); relay.post("bob", b'{"from":"x"}')
    a.send("bob", b"ok")
    assert b.receive_all() == [("alice", b"ok")]
    assert len(b.errors) == 2


def test_message_without_session_or_init_rejected():
    relay, a, b = make_pair()
    relay.post("bob", encode_envelope("alice", None, bytes(40), b"x" * 40))
    assert b.receive_all() == [] and b.errors


def test_forged_init_wrong_ek_fails_to_decrypt():
    relay, a, b = make_pair()
    a.send("bob", b"x")
    sender, init, h, c = decode_envelope(relay._queues["bob"][0])
    relay._queues["bob"][0] = encode_envelope(sender, dataclasses.replace(init, ek=bytes([9]) * 32), h, c)
    assert b.receive_all() == [] and b.errors


def test_spk_signature_binds_identity_dh_key():
    """Тот же ключ подписи, но чужой DH-ключ идентичности: подпись обязана не пройти."""
    bob, mallory, alice = IdentityKeyPair(), IdentityKeyPair(), IdentityKeyPair()
    s = PrekeyStore(bob)
    spliced = IdentityPublic(mallory.public.dh, bob.public.sig)
    with pytest.raises(E2EEError):
        x3dh_initiate(alice, PrekeyBundle(spliced, 1, s.spk, s.spk_sig))


def test_relay_hands_out_each_opk_once():
    relay, a, b = make_pair()
    ids = [relay.fetch_bundle("bob").opk_id for _ in range(5)]
    assert len(set(ids)) == 5 and relay.fetch_bundle("bob").opk_id is None


def test_relabel_at_first_contact_is_inherent_tofu_limit():
    """Граница TOFU: на ПЕРВОМ контакте relay вправе назвать отправителя как угодно. Ловится только сверкой safety number."""
    import json
    relay, a, b = make_pair()
    a.send("bob", b"hello")
    env = json.loads(relay._queues["bob"][0]); env["from"] = "carol"
    relay._queues["bob"][0] = json.dumps(env, sort_keys=True).encode()
    assert b.receive_all() == [("carol", b"hello")]
    assert safety_number(b.identity.public, b.known["carol"]) == safety_number(a.identity.public, b.identity.public)


def test_relabel_of_known_contact_is_rejected():
    """Найдено при формальном анализе: поле from вне криптографии; relay мог выдать сообщение Алисы за сообщение Кэрол."""
    import json
    relay, a, b = make_pair()
    a.send("bob", b"1"); b.receive_all(); b.send("alice", b"r"); a.receive_all()
    a.send("bob", b"2")
    env = json.loads(relay._queues["bob"][0]); env["from"] = "carol"
    relay._queues["bob"][0] = json.dumps(env, sort_keys=True).encode()
    assert b.receive_all() == [] and b.errors


def test_one_name_cannot_take_two_identities_either():
    relay, a, b = make_pair()
    a.send("bob", b"x"); b.receive_all()
    imposter = Client("alice2", relay)
    with pytest.raises(IdentityChanged):
        b._trust("alice2", a.identity.public)


def test_spk_rotation_keeps_one_previous_generation_and_wipes_older():
    relay, a, b = make_pair()
    old_bundle = relay.fetch_bundle("bob")                  # Алиса получила bundle ДО ротации
    old_id = b.store.spk_id
    b.store.rotate_spk(); b.publish_prekeys()
    a2_id = IdentityKeyPair()
    sk, ad, init = x3dh_initiate(a2_id, old_bundle)         # сообщение «в полёте» на старый SPK
    assert x3dh_respond(b.store, init)[0] == sk             # ещё принимается
    b.store.rotate_spk()                                    # второе поколение: старый стёрт
    with pytest.raises(E2EEError, match="устаревший"):
        x3dh_respond(b.store, init)
    assert old_id not in b.store._spks and b.store.spk_id == old_id + 2


def test_new_bundles_use_rotated_spk_and_signature_valid():
    relay, a, b = make_pair()
    b.store.rotate_spk(); b.publish_prekeys()
    bundle = relay.fetch_bundle("bob")
    assert bundle.spk == b.store.spk and bundle.spk_id == b.store.spk_id
    a.send("bob", b"after rotation"); assert b.receive_all() == [("alice", b"after rotation")]


def test_compromised_spk_does_not_open_sessions_after_it_was_rotated_out():
    """Атакующий украл SPK-ключ. После двух ротаций сохранённый старый SPK бесполезен для новых сессий."""
    relay, a, b = make_pair()
    stolen_priv = b.store.spk_priv; stolen_id = b.store.spk_id; stolen_pub = b.store.spk
    b.store.rotate_spk(); b.store.rotate_spk(); b.publish_prekeys()
    assert stolen_id not in b.store._spks
    bundle = relay.fetch_bundle("bob")
    assert bundle.spk_id != stolen_id and bundle.spk != stolen_pub
