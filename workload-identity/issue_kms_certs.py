"""Выпускает SVID для KMS: coordinator + node-1..N в каталоги certs/<имя>/{svid.crt,svid.key,bundle.crt}.
Использование: python issue_kms_certs.py <каталог> [число узлов]  (затем COORDINATOR_SPIFFE_ID=spiffe://kms.local/coordinator)"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from spire import SpireServer, Agent

TD = "kms.local"
out = sys.argv[1] if len(sys.argv) > 1 else "certs"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
s = SpireServer(TD)
for name in ["coordinator"] + [f"node-{i}" for i in range(1, n + 1)]:
    Agent(s, s.create_join_token(f"spiffe://{TD}/{name}")).write_files(os.path.join(out, name))
print(f"SVID выпущены в {out}/ (TTL {s.ttl}); COORDINATOR_SPIFFE_ID=spiffe://{TD}/coordinator")
