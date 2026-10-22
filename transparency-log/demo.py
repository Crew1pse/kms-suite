"""Сквозная демонстрация без сети: KMS-события -> журнал -> монитор -> попытка переписать историю.
Запуск:  pip install -r requirements.txt && python demo.py"""
import json, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from monitor import Monitor, LogClient, MonitorAlert
from server import create_app
from tlog import TransparencyLog

TOKEN = "demo-token"; AUTH = {"Authorization": f"Bearer {TOKEN}"}
tmp = tempfile.mkdtemp(); key = Ed25519PrivateKey.generate()   # публичный ключ монитор знает заранее
honest = TransparencyLog(f"{tmp}/log.db", key)
server = TestClient(create_app(honest, TOKEN))

def kms_event(i, op): return json.dumps({"v": 1, "node_id": 1, "op": op, "n": i}, sort_keys=True).encode()
class Switch:   # "сетевой путь" монитора к серверу
    def __init__(self, c): self.c = c
    def get(self, *a, **k): return self.c.get(*a, **k)

net = Switch(server); monitor = Monitor(LogClient(net), key.public_key())
ops = ["store", "retrieve", "retrieve", "shred", "store", "retrieve", "shred", "store"]
for i, op in enumerate(ops[:5]):
    server.post("/v1/entries", content=kms_event(i, op), headers=AUTH)
print("1. монитор забирает 5 событий, каждое проверено доказательством включения:")
for i, d in monitor.new_entries(): print("  ", i, json.loads(d)["op"])
print("   проверенный размер:", monitor.trusted["tree_size"], "корень:", monitor.trusted["root_hash"][:16], "...")

for i, op in enumerate(ops[5:], 5):
    server.post("/v1/entries", content=kms_event(i, op), headers=AUTH)
print("2. журнал вырос; монитор проверяет согласованность (старое дерево - префикс нового):")
for i, d in monitor.new_entries(): print("  ", i, json.loads(d)["op"])
print("   проверенный размер:", monitor.trusted["tree_size"])

print("3. оператор с ключом подписи пытается скрыть событие №3 (shred) и пересобирает журнал:")
evil = TransparencyLog(f"{tmp}/evil.db", key)
for i, op in enumerate(ops):
    evil.append(kms_event(i, "retrieve" if i == 3 else op))
net.c = TestClient(create_app(evil, TOKEN))
try:
    monitor.update(); print("   !!! подмена НЕ обнаружена")
except MonitorAlert as e:
    print("   ТРЕВОГА:", type(e).__name__, "-", e)
