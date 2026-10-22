from e2ee import *
from relay import Relay, Client


def make_pair():
    relay = Relay()
    a, b = Client("alice", relay), Client("bob", relay)
    b.publish_prekeys(); a.publish_prekeys()
    return relay, a, b


def make_ratchets(max_skip=1000):
    bob_id = IdentityKeyPair(); alice_id = IdentityKeyPair()
    store = PrekeyStore(bob_id); (oid, opk), = store.new_opks(1)
    bundle = PrekeyBundle(bob_id.public, store.spk_id, store.spk, store.spk_sig, oid, opk)
    sk, ad, init = x3dh_initiate(alice_id, bundle)
    sk2, ad2 = x3dh_respond(store, init)
    assert sk == sk2 and ad == ad2
    return (Ratchet.init_alice(sk, store.spk, ad, max_skip),
            Ratchet.init_bob(sk2, store.spk_priv, store.spk, ad2, max_skip))


def send(frm, to, msg, extra=b""):
    h, c = frm.encrypt(msg, extra)
    return to.decrypt(h, c, extra)
