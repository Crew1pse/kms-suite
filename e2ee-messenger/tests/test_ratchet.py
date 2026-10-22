import pytest
from hypothesis import given, settings, strategies as st
from helpers import *


def test_ping_pong_long():
    a, b = make_ratchets()
    for i in range(60):
        assert send(a, b, b"a%d" % i) == b"a%d" % i
        assert send(b, a, b"b%d" % i) == b"b%d" % i


def test_burst_same_direction():
    a, b = make_ratchets()
    for i in range(20):
        assert send(a, b, b"%d" % i) == b"%d" % i


def test_bob_cannot_send_first():
    _, b = make_ratchets()
    with pytest.raises(E2EEError):
        b.encrypt(b"x")


def test_out_of_order_and_across_ratchet():
    a, b = make_ratchets()
    m = [a.encrypt(b"m%d" % i) for i in range(5)]
    for i in (3, 0, 4, 1, 2):
        assert b.decrypt(*m[i]) == b"m%d" % i
    # ответ, затем старые сообщения предыдущей цепочки после DH-шага
    m2 = [a.encrypt(b"n%d" % i) for i in range(3)]
    assert b.decrypt(*m2[2]) == b"n2"
    r = b.encrypt(b"reply"); assert a.decrypt(*r) == b"reply"
    m3 = a.encrypt(b"after"); assert b.decrypt(*m3) == b"after"
    assert b.decrypt(*m2[0]) == b"n0" and b.decrypt(*m2[1]) == b"n1"


def test_replay_rejected():
    a, b = make_ratchets()
    h, c = a.encrypt(b"x")
    assert b.decrypt(h, c) == b"x"
    with pytest.raises(DecryptionError):
        b.decrypt(h, c)


def test_replay_of_skipped_message_only_once():
    a, b = make_ratchets()
    m = [a.encrypt(b"%d" % i) for i in range(3)]
    b.decrypt(*m[2]); b.decrypt(*m[0])
    with pytest.raises(DecryptionError):
        b.decrypt(*m[0])


def test_skip_limit():
    a, b = make_ratchets(max_skip=10)
    msgs = [a.encrypt(b"x") for _ in range(30)]
    with pytest.raises(SkipLimitExceeded):
        b.decrypt(*msgs[25])
    assert b.decrypt(*msgs[0]) == b"x"       # состояние не испорчено


@pytest.mark.parametrize("what", ["ct", "header_n", "header_dh", "header_pn", "truncate", "extra_ad"])
def test_tamper_rejected_and_state_unchanged(what):
    a, b = make_ratchets()
    send(a, b, b"warmup"); send(b, a, b"warmup2")
    h, c = a.encrypt(b"secret")
    extra = b""
    if what == "ct": c = c[:-1] + bytes([c[-1] ^ 1])
    elif what == "header_n": h = h[:-1] + bytes([h[-1] ^ 1])
    elif what == "header_dh": h = bytes([h[0] ^ 1]) + h[1:]
    elif what == "header_pn": h = h[:33] + bytes([h[33] ^ 1]) + h[34:]
    elif what == "truncate": c = c[:-3]
    elif what == "extra_ad": extra = b"x"
    with pytest.raises(DecryptionError):
        b.decrypt(h, c, extra)
    # настоящее сообщение всё ещё расшифровывается: подделка не сдвинула храповик
    h, c = a.encrypt(b"real") if what == "x" else (None, None)
    a2, b2 = make_ratchets()
    hh, cc = a2.encrypt(b"ok")
    bad = bytes([hh[0] ^ 1]) + hh[1:]
    with pytest.raises(DecryptionError):
        b2.decrypt(bad, cc)
    assert b2.decrypt(hh, cc) == b"ok"


def test_bad_header_length():
    _, b = make_ratchets()
    with pytest.raises(DecryptionError):
        b.decrypt(b"short", b"x" * 40)


def test_wrong_session_cannot_decrypt():
    a, _ = make_ratchets(); _, b2 = make_ratchets()
    with pytest.raises(DecryptionError):
        b2.decrypt(*a.encrypt(b"x"))


def test_associated_data_binds_identities():
    a, b = make_ratchets()
    b.ad = b"other"
    with pytest.raises(DecryptionError):
        b.decrypt(*a.encrypt(b"x"))


def test_ciphertexts_differ_for_same_plaintext():
    a, _ = make_ratchets()
    assert a.encrypt(b"same")[1] != a.encrypt(b"same")[1]


def test_forward_secrecy_stolen_state_cannot_read_past():
    a, b = make_ratchets()
    send(a, b, b"1"); send(b, a, b"2")
    old = a.encrypt(b"past secret")
    b.decrypt(*old)
    send(b, a, b"3"); send(a, b, b"4")
    stolen = b.snapshot()                    # атакующий украл состояние Боба сейчас
    with pytest.raises(DecryptionError):     # прошлое сообщение прочитать нельзя
        stolen.decrypt(*old)


def test_post_compromise_security_heals():
    a, b = make_ratchets()
    send(a, b, b"1"); send(b, a, b"2")
    stolen = b.snapshot()
    # пока обмен идёт без участия атакующего, происходит DH-шаг с новыми ключами
    send(a, b, b"3"); send(b, a, b"4"); send(a, b, b"5"); send(b, a, b"6")
    h, c = a.encrypt(b"after healing")
    with pytest.raises(DecryptionError):
        stolen.decrypt(h, c)
    assert b.decrypt(h, c) == b"after healing"


def test_stolen_state_reads_until_healing():
    a, b = make_ratchets()
    send(a, b, b"1")
    stolen = b.snapshot()
    h, c = a.encrypt(b"before healing")      # в той же цепочке - украденное состояние читает
    assert stolen.decrypt(h, c) == b"before healing"


@settings(max_examples=40, deadline=None)
@given(st.lists(st.tuples(st.booleans(), st.binary(max_size=64)), min_size=1, max_size=25), st.randoms())
def test_random_schedule_with_reordering(script, rnd):
    a, b = make_ratchets()
    pending = {True: [], False: []}      # True = a->b
    # b не может писать, пока не получил первое сообщение
    started = False
    delivered = 0
    for a_to_b, msg in script:
        if not a_to_b and not started:
            a_to_b = True
        src, dst = (a, b) if a_to_b else (b, a)
        pending[a_to_b].append((msg, *src.encrypt(msg)))
        # случайно доставляем часть накопленного в случайном порядке
        for d in (True, False):
            q = pending[d]
            rnd.shuffle(q)
            take = q[: rnd.randint(0, len(q))]
            del q[: len(take)]
            for m, h, c in take:
                assert (b if d else a).decrypt(h, c) == m
                delivered += 1
                started = started or d
    for d in (True, False):
        for m, h, c in pending[d]:
            assert (b if d else a).decrypt(h, c) == m


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=80), st.binary(max_size=120))
def test_garbage_never_crashes(h, c):
    _, b = make_ratchets()
    try:
        b.decrypt(h, c)
    except DecryptionError:
        pass


def test_header_pn_and_n_are_authenticated_in_same_chain():
    a, b = make_ratchets()
    send(a, b, b"1")
    h, c = a.encrypt(b"2")
    for idx in (35, 39):                      # последний байт pn и n
        bad = h[:idx] + bytes([h[idx] ^ 1]) + h[idx + 1:]
        with pytest.raises(DecryptionError):
            b.decrypt(bad, c)
    assert b.decrypt(h, c) == b"2"
