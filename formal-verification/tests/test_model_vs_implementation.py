"""Мост между моделью и настоящим кодом мессенджера: модель обязана предсказывать, что РЕАЛЬНЫЙ код ломается ровно при тех утечках."""
from itertools import combinations
import dataclasses, pytest
import e2ee
from e2ee import *
from helpers import make_ratchets
from models import x3dh, healing_report, owner

ALL = ["ik_a", "ik_b", "spk_b", "ek_a", "opk_b"]


def run_real(with_opk):
    """Настоящий X3DH; перехватываем эфемерный ключ Алисы, который код сразу выбрасывает."""
    captured = []
    real_gen = e2ee._gen
    e2ee._gen = lambda: captured.append(real_gen()) or captured[-1]
    try:
        alice, bob = IdentityKeyPair(), IdentityKeyPair()
        store = PrekeyStore(bob)
        oid, opk = store.new_opks(1)[0] if with_opk else (None, None)
        opk_priv = store._opks[oid] if with_opk else None
        spk_priv = store.spk_priv
        captured.clear()
        sk, ad, init = x3dh_initiate(alice, PrekeyBundle(bob.public, store.spk_id, store.spk, store.spk_sig, oid, opk))
        ek_priv = captured[0][0]
    finally:
        e2ee._gen = real_gen
    secrets = {"ik_a": alice.dh_priv, "ik_b": bob.dh_priv, "spk_b": spk_priv, "ek_a": ek_priv}
    if with_opk:
        secrets["opk_b"] = opk_priv
    pubs = dict(ik_a=alice.public.dh, ik_b=bob.public.dh, spk_b=store.spk, ek_a=init.ek, opk_b=opk)
    return sk, secrets, pubs


def attacker_sk(S, secrets, pubs, with_opk):
    """Пассивный атакующий с утёкшими секретами S строит ключ, используя ТОЛЬКО доступные ему DH."""
    def pick(a, b):                      # DH(a,b): нужен секрет любой из сторон
        if a in S: return e2ee._dh(secrets[a], pubs[b])
        if b in S: return e2ee._dh(secrets[b], pubs[a])
        return None
    parts = [pick("ik_a", "spk_b"), pick("ek_a", "ik_b"), pick("ek_a", "spk_b")]
    if with_opk:
        parts.append(pick("ek_a", "opk_b"))
    if any(p is None for p in parts):
        return None
    return e2ee._hkdf(b"\xff" * 32 + b"".join(parts), bytes(32), b"X3DH-v1", 32)


@pytest.mark.parametrize("with_opk", [True, False])
def test_model_predicts_real_implementation_for_every_leak_set(with_opk):
    sk, secrets, pubs = run_real(with_opk)
    names = [n for n in ALL if n in secrets]
    model = x3dh(with_opk=with_opk)
    checked = 0
    for r in range(len(names) + 1):
        for S in combinations(names, r):
            got = attacker_sk(set(S), secrets, pubs, with_opk)
            real_broken = got == sk
            assert real_broken == model.broken_by(S), f"расхождение модели и кода при утечке {S}"
            if got is not None:
                assert got == sk       # если атакующий смог посчитать - это именно настоящий ключ
            checked += 1
    assert checked == 2 ** len(names)


@pytest.mark.parametrize("t", range(1, 7))
@pytest.mark.parametrize("party", ["A", "B"])
def test_model_predicts_real_ratchet_healing(t, party):
    """Модель: с какого шага корневой ключ снова недоступен. Код: первое входящее сообщение, которое украденная копия не читает."""
    a, b = make_ratchets(); p = {"A": a, "B": b}
    stolen, msgs, total = None, [], 14
    for n in range(1, total + 1):
        s = "A" if n % 2 else "B"; r = "B" if s == "A" else "A"
        h, c = p[s].encrypt(b"m%d" % n); p[r].decrypt(h, c); msgs.append((s, h, c))
        if n == t:
            stolen = p[party].snapshot()
    real = next(n for n in range(t + 1, total + 1) if msgs[n - 1][0] != party and _fails(stolen, msgs[n - 1]))
    k = t + healing_report(10)[(t, party)]
    predicted = next(n for n in range(k, total + 1) if msgs[n - 1][0] != party)
    assert real == predicted


def _fails(stolen, m):
    try:
        stolen.decrypt(m[1], m[2]); return False
    except DecryptionError:
        return True


# ---------- активные атаки на реальном коде ----------
def setup_pair(with_opk=True):
    alice, bob = IdentityKeyPair(), IdentityKeyPair()
    store = PrekeyStore(bob)
    oid, opk = store.new_opks(1)[0] if with_opk else (None, None)
    return alice, bob, store, PrekeyBundle(bob.public, store.spk_id, store.spk, store.spk_sig, oid, opk)


def forge_initiator(victim_pub: IdentityPublic, bob_pub, bundle, dh1_secret_fn):
    """Мэллори выдаёт себя за victim: сама выбирает эфемерный ключ, DH1 считает доступным ей способом."""
    ek_priv, ek_pub = e2ee._gen()
    parts = [dh1_secret_fn(), e2ee._dh(ek_priv, bob_pub.dh), e2ee._dh(ek_priv, bundle.spk)]
    if bundle.opk is not None:
        parts.append(e2ee._dh(ek_priv, bundle.opk))
    sk = e2ee._hkdf(b"\xff" * 32 + b"".join(parts), bytes(32), b"X3DH-v1", 32)
    return sk, victim_pub.dh + bob_pub.dh, InitialHeader(victim_pub, ek_pub, bundle.spk_id, bundle.opk_id)


def test_leaked_spk_lets_attacker_impersonate_anyone_to_bob():
    """Следствие модели: {spk_b} достаточно, чтобы Боб принял чужое лицо. Подтверждено на реальном коде."""
    alice, bob, store, bundle = setup_pair()
    stolen_spk = store.spk_priv
    sk, ad, init = forge_initiator(alice.public, bob.public, bundle, lambda: e2ee._dh(stolen_spk, alice.public.dh))
    mallory = Ratchet.init_alice(sk, bundle.spk, ad)
    sk_bob, ad_bob = x3dh_respond(store, init)
    bob_side = Ratchet.init_bob(sk_bob, *store.spk_keys(init.spk_id)[:1], bundle.spk, ad_bob)
    assert bob_side.decrypt(*mallory.encrypt(b"I am Alice, send me the keys")) == b"I am Alice, send me the keys"


def test_leaked_ik_b_alone_does_not_allow_impersonation_kci_resistance():
    alice, bob, store, bundle = setup_pair()
    sk, ad, init = forge_initiator(alice.public, bob.public, bundle, lambda: e2ee._dh(bob.dh_priv, alice.public.dh))  # неверный DH1
    mallory = Ratchet.init_alice(sk, bundle.spk, ad)
    sk_bob, ad_bob = x3dh_respond(store, init)
    bob_side = Ratchet.init_bob(sk_bob, store.spk_priv, bundle.spk, ad_bob)
    with pytest.raises(DecryptionError):
        bob_side.decrypt(*mallory.encrypt(b"x"))


def test_rotation_ends_impersonation_with_stolen_spk():
    alice, bob, store, bundle = setup_pair()
    stolen_spk = store.spk_priv
    store.rotate_spk(); store.rotate_spk()
    _, _, init = forge_initiator(alice.public, bob.public, bundle, lambda: e2ee._dh(stolen_spk, alice.public.dh))
    with pytest.raises(E2EEError, match="устаревший"):
        x3dh_respond(store, init)


def test_identity_misbinding_attack_fails():
    """Мэллори подменяет в init ключ идентичности Алисы на свой, оставляя остальное: ключи расходятся."""
    alice, bob, store, bundle = setup_pair()
    sk, ad, init = x3dh_initiate(alice, bundle)
    mallory = IdentityKeyPair()
    sk2, ad2 = x3dh_respond(store, dataclasses.replace(init, identity=mallory.public))
    assert sk2 != sk and ad2 != ad


def test_reflection_attack_fails():
    a, b = make_ratchets()
    h, c = a.encrypt(b"to bob")
    with pytest.raises(DecryptionError):
        a.decrypt(h, c)                      # сообщение, отражённое обратно отправителю


def test_cross_session_splice_fails():
    a1, b1 = make_ratchets(); a2, b2 = make_ratchets()
    h, c = a1.encrypt(b"for session 1")
    with pytest.raises(DecryptionError):
        b2.decrypt(h, c)
