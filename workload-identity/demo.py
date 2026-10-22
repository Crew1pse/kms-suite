import datetime as dt, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from spire import SpireServer, Agent, AttestationError
from svid import verify_svid, make_csr, new_key, SvidError

TD = "prod.example"; ID = f"spiffe://{TD}/ns/kms/coordinator"
now = dt.datetime.now(dt.timezone.utc)
s = SpireServer(TD)
tok = s.create_join_token(ID)
a = Agent(s, tok)
print("1. SVID выдан:", verify_svid(a.cert, s.bundle(), TD), "TTL", a.cert.not_valid_after_utc - a.cert.not_valid_before_utc)
try: Agent(s, tok)
except AttestationError as e: print("2. Повтор токена отвергнут:", e)
print("3. Ротация на 6-й минуте:", a.rotate_if_needed(now + dt.timedelta(minutes=6)), "(новый ключ, тот же ID)")
try: verify_svid(a.cert, s.bundle(), TD, now=now + dt.timedelta(hours=1))
except SvidError as e: print("4. Через час SVID мёртв сам:", e)
b = Agent(s, s.create_join_token(ID)); s.rotate_ca(); a2 = s.renew(b.cert, make_csr(new_key()))
print("5. Ротация CA: оба принимаются в новом bundle:", verify_svid(a2, s.bundle(), TD) == verify_svid(b.cert, s.bundle(), TD))
s.retire_old_cas()
try: verify_svid(b.cert, s.bundle(), TD)
except SvidError as e: print("6. После вывода старого CA старый SVID отвергнут")
