import random
import frost
from dkg import DKGParticipant


def sign_with(pkg, shares, ids, message):
    signers = {i: frost.Signer(shares[i]) for i in ids}
    commitments = [s.commit() for s in signers.values()]
    sig_shares = [s.sign(message, commitments) for s in signers.values()]
    return frost.aggregate(pkg, message, commitments, sig_shares)


def run_dkg(n, t, session=b"session-1"):
    parts = {i: DKGParticipant(i, n, t, session) for i in range(1, n + 1)}
    r1 = [p.round1() for p in parts.values()]
    r2 = {i: p.round2(r1) for i, p in parts.items()}
    out = {}
    for i, p in parts.items():
        out[i] = p.finalize([pk for sender in r2.values() for pk in sender if pk.receiver == i])
    shares = {i: o[0] for i, o in out.items()}
    pkgs = {i: o[1] for i, o in out.items()}
    return shares, pkgs, parts, r1, r2
