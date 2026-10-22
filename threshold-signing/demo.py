"""Сквозной сценарий: DKG без дилера -> пороговая подпись -> обычный Ed25519-верификатор -> журнал прозрачности.
Запуск: pip install -r requirements.txt -r ../transparency-log/requirements.txt && python demo.py"""
import os, sys, random, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "src"), os.path.join(HERE, "tests"), os.path.join(HERE, "..", "transparency-log", "src")]
import frost
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from helpers import run_dkg
from dkg import DKGParticipant, DKGError, Round1Package

N, T = 5, 3
print(f"1. DKG {T}-из-{N} без доверенного дилера")
shares, pkgs, *_ = run_dkg(N, T, session=b"demo")
pk = pkgs[1].group_public_key
print("   групповой публичный ключ:", pk.hex())
print("   полный секретный ключ не существует ни у кого; у каждого участника только своя доля")

print("2. Подпись кворумом {2,4,5} (остальные узлы офлайн)")
signers = {i: frost.Signer(shares[i]) for i in (2, 4, 5)}
msg = b"rotate key kms-prod-7"
coms = [s.commit() for s in signers.values()]
sig = frost.aggregate(pkgs[1], msg, coms, [s.sign(msg, coms) for s in signers.values()])
Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
print("   подпись проверена обычным Ed25519-верификатором (cryptography):", sig.hex()[:32], "...")

print("3. Два узла (меньше порога) подписать не могут")
two = {i: frost.Signer(shares[i]) for i in (1, 2)}
c2 = [s.commit() for s in two.values()]
try: two[1].sign(msg, c2)
except frost.FrostError as e: print("   отказ:", e)

print("4. Один участник подсовывает неверную долю подписи - агрегатор называет виновного")
signers = {i: frost.Signer(shares[i]) for i in (1, 3, 5)}
coms = [s.commit() for s in signers.values()]
sh = [s.sign(msg, coms) for s in signers.values()]
sh[1] = frost.SignatureShare(sh[1].identifier, (sh[1].z + 1) % (2**252))
try: frost.aggregate(pkgs[1], msg, coms, sh)
except frost.InvalidShare as e: print("  ", e)

print("5. Повторное использование nonce запрещено")
s = frost.Signer(shares[1]); others = [frost.Signer(shares[i]).commit() for i in (2, 3)]
c = [s.commit()] + others; s.sign(b"first", c)
try: s.sign(b"second", c)
except frost.NonceReuseError as e: print("   отказ:", e)

print("6. Атака 'навязать ключ' (rogue key) в DKG отклоняется доказательством владения")
parts = {i: DKGParticipant(i, 4, 2, b"atk") for i in range(1, 5)}
r1 = [p.round1() for p in parts.values()]
from ed25519_group import point_sub, base_mul, IDENTITY, point_add, random_scalar
honest = IDENTITY
for p in r1[:3]: honest = point_add(honest, p.commitments[0])
forged = Round1Package(4, (point_sub(base_mul(42), honest), r1[3].commitments[1]), base_mul(random_scalar()), random_scalar())
try: parts[1].round2(r1[:3] + [forged])
except DKGError as e: print("  ", e)

print("7. Журнал прозрачности, подписывающий STH пороговым ключом")
from tlog import TransparencyLog, verify_sth_signature
import tempfile
class ThresholdKey:
    def public_key(self): return Ed25519PublicKey.from_public_bytes(pk)
    def sign(self, m):
        ids = random.sample(range(1, N + 1), T)
        ss = {i: frost.Signer(shares[i]) for i in ids}; cs = [x.commit() for x in ss.values()]
        return frost.aggregate(pkgs[1], m, cs, [x.sign(m, cs) for x in ss.values()])
log = TransparencyLog(tempfile.mkdtemp() + "/l.db", ThresholdKey())
for i in range(3): log.append(json.dumps({"n": i}).encode())
sth = log.latest_sth()
print("   STH размера", sth["tree_size"], "подписан кворумом; проверка штатным верификатором журнала:",
      verify_sth_signature(ThresholdKey().public_key(), sth))
