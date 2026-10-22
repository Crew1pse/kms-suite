"""Монитор: независимый наблюдатель, который не доверяет серверу журнала.
Хранит последний проверенный STH и при каждом обновлении требует доказательство согласованности."""
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from merkle import verify_consistency, verify_inclusion
from tlog import verify_sth_signature


class MonitorAlert(Exception):
    """Журнал вёл себя недопустимо."""


class SignatureInvalid(MonitorAlert): pass
class RollbackDetected(MonitorAlert): pass       # размер дерева уменьшился
class ForkDetected(MonitorAlert): pass           # тот же размер, другой корень
class InconsistentHistory(MonitorAlert): pass    # старая история переписана
class InclusionFailed(MonitorAlert): pass


class LogClient:
    """Тонкий клиент над httpx-подобным объектом (httpx.Client(base_url=...) или TestClient)."""

    def __init__(self, http):
        self.http = http

    def _get(self, path, **params):
        r = self.http.get(path, params=params)
        r.raise_for_status()
        return r.json()

    def sth(self): return self._get("/v1/sth")
    def entry(self, i): return base64.b64decode(self._get(f"/v1/entries/{i}")["data"])

    def inclusion(self, index, size):
        return [bytes.fromhex(h) for h in self._get("/v1/proof/inclusion", index=index, tree_size=size)["audit_path"]]

    def consistency(self, first, second):
        return [bytes.fromhex(h) for h in self._get("/v1/proof/consistency", first=first, second=second)["consistency_path"]]


class Monitor:
    def __init__(self, client: LogClient, public_key: Ed25519PublicKey, trusted_sth: dict | None = None):
        self.client, self.public_key = client, public_key
        self.trusted = trusted_sth          # последний проверенный STH (сохраняйте на диск между запусками)
        self._scanned = 0

    def update(self) -> dict:
        new = self.client.sth()
        if not verify_sth_signature(self.public_key, new):
            raise SignatureInvalid("подпись STH недействительна")
        old = self.trusted
        if old is not None:
            if new["tree_size"] < old["tree_size"]:
                raise RollbackDetected(f"размер уменьшился: {old['tree_size']} -> {new['tree_size']}")
            if new["tree_size"] == old["tree_size"]:
                if new["root_hash"] != old["root_hash"]:
                    raise ForkDetected("тот же размер, но другой корень")
            else:
                proof = self.client.consistency(old["tree_size"], new["tree_size"])
                if not verify_consistency(old["tree_size"], new["tree_size"], bytes.fromhex(old["root_hash"]),
                                          bytes.fromhex(new["root_hash"]), proof):
                    raise InconsistentHistory("новое дерево не является продолжением проверенного")
        self.trusted = new
        return new

    def check_inclusion(self, data: bytes, index: int):
        """Запись действительно в журнале на проверенном размере."""
        if self.trusted is None:
            raise MonitorAlert("нет проверенного STH: вызовите update()")
        size = self.trusted["tree_size"]
        proof = self.client.inclusion(index, size)
        if not verify_inclusion(data, index, size, proof, bytes.fromhex(self.trusted["root_hash"])):
            raise InclusionFailed(f"запись {index} не доказана")

    def new_entries(self):
        """Выдаёт (индекс, данные) ещё не просмотренных записей, каждая проверена доказательством включения."""
        self.update()
        for i in range(self._scanned, self.trusted["tree_size"]):
            data = self.client.entry(i)
            self.check_inclusion(data, i)
            yield i, data
            self._scanned = i + 1
