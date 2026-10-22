"""Цена постквантовой части: размеры и время. Запуск: python bench_pq.py"""
import os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from e2ee import *
from pqxdh import *

def t(f, n=20):
    s = time.perf_counter()
    for _ in range(n): r = f()
    return (time.perf_counter() - s) / n * 1000, r

bob, alice = IdentityKeyPair(), IdentityKeyPair()
s, pq = PrekeyStore(bob), PQPrekeyStore(bob)
oid, opk = s.new_opks(1)[0]
base = PrekeyBundle(bob.public, s.spk_id, s.spk, s.spk_sig, oid, opk)
pid, pek, psig = pq.new_key(False)
b = PQBundle(base, pid, pek, psig)
ms_c, _ = t(lambda: x3dh_initiate(alice, base))
ms_p, (sk, ad, h) = t(lambda: pqxdh_initiate(alice, b))
print(f"{'':20}{'X3DH':>10}{'PQXDH':>10}")
print(f"{'initiate, мс':20}{ms_c:10.2f}{ms_p:10.2f}")
print(f"{'prekey bundle, байт':20}{32+32+32+64+32:>10}{32+32+32+64+32+EK_LEN+64:>10}")
print(f"{'init header, байт':20}{32+32+32+8:>10}{32+32+32+8+CT_LEN:>10}   (ek ML-KEM {EK_LEN}, ct {CT_LEN})")
