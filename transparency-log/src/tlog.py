"""Журнал прозрачности: append-only SQLite + подписанные корни (STH, Ed25519)."""
import sqlite3
import struct
import threading
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from merkle import MerkleTree, leaf_hash

STH_DOMAIN = b"KMS-TL-STH-v1\x00"   # доменное разделение: подпись STH нельзя выдать за подпись чего-то другого


class LogCorrupted(Exception):
    pass


def sth_message(tree_size: int, root: bytes, timestamp: int) -> bytes:
    return STH_DOMAIN + struct.pack(">QQ", tree_size, timestamp) + root


def verify_sth_signature(public_key: Ed25519PublicKey, sth: dict) -> bool:
    try:
        public_key.verify(bytes.fromhex(sth["signature"]),
                          sth_message(sth["tree_size"], bytes.fromhex(sth["root_hash"]), sth["timestamp"]))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError):
        return False


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (idx INTEGER PRIMARY KEY, data BLOB NOT NULL, leaf_hash BLOB NOT NULL, ts INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sths (id INTEGER PRIMARY KEY AUTOINCREMENT, tree_size INTEGER NOT NULL, root_hash BLOB NOT NULL,
                                 ts INTEGER NOT NULL, signature BLOB NOT NULL);
CREATE TRIGGER IF NOT EXISTS entries_no_update BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS sths_no_update BEFORE UPDATE ON sths BEGIN SELECT RAISE(ABORT, 'append-only'); END;
CREATE TRIGGER IF NOT EXISTS sths_no_delete BEFORE DELETE ON sths BEGIN SELECT RAISE(ABORT, 'append-only'); END;
"""


class TransparencyLog:
    def __init__(self, db_path: str, signing_key: Ed25519PrivateKey):
        self._key = signing_key
        self.public_key = signing_key.public_key()
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.executescript(_SCHEMA)
        self.tree = MerkleTree()
        self._load_and_self_check()

    # ---- загрузка с самопроверкой: ловит правки файла БД "в обход" триггеров ----
    def _load_and_self_check(self):
        for i, (idx, data, lh) in enumerate(self._db.execute("SELECT idx, data, leaf_hash FROM entries ORDER BY idx")):
            if idx != i:
                raise LogCorrupted(f"в индексах дыра: ожидался {i}, найден {idx}")
            if leaf_hash(bytes(data)) != bytes(lh):
                raise LogCorrupted(f"хэш листа {i} не совпадает с данными")
            self.tree.leaves.append(bytes(lh))
        for size, root, ts, sig in self._db.execute("SELECT tree_size, root_hash, ts, signature FROM sths ORDER BY id"):
            if size > len(self.tree):
                raise LogCorrupted(f"STH размера {size} при {len(self.tree)} записях: записи удалены")
            if self.tree.root(size) != bytes(root):
                raise LogCorrupted(f"корень дерева размера {size} не совпадает с ранее подписанным STH")
            if not verify_sth_signature(self.public_key, self._sth_dict(size, bytes(root), ts, bytes(sig))):
                raise LogCorrupted(f"подпись STH размера {size} недействительна")

    @staticmethod
    def _sth_dict(size, root, ts, sig):
        return {"tree_size": size, "root_hash": root.hex(), "timestamp": ts, "signature": sig.hex()}

    def _sign_and_store_sth(self) -> dict:
        size, root, ts = len(self.tree), self.tree.root(), int(time.time())
        sig = self._key.sign(sth_message(size, root, ts))
        self._db.execute("INSERT INTO sths (tree_size, root_hash, ts, signature) VALUES (?,?,?,?)", (size, root, ts, sig))
        self._db.commit()
        return self._sth_dict(size, root, ts, sig)

    # ---- публичный API ----
    def append(self, data: bytes) -> tuple[int, dict]:
        """Запись добавляется атомарно; возвращает (индекс, новый подписанный STH)."""
        with self._lock:
            idx, lh = len(self.tree), leaf_hash(data)
            try:
                self._db.execute("INSERT INTO entries (idx, data, leaf_hash, ts) VALUES (?,?,?,?)",
                                 (idx, data, lh, int(time.time())))
                self.tree.leaves.append(lh)
                sth = self._sign_and_store_sth()
            except Exception:
                self._db.rollback()
                if len(self.tree) > idx:
                    self.tree.leaves.pop()
                raise
            return idx, sth

    def latest_sth(self) -> dict:
        with self._lock:
            row = self._db.execute("SELECT tree_size, root_hash, ts, signature FROM sths ORDER BY id DESC LIMIT 1").fetchone()
            if row is None or row[0] != len(self.tree):
                return self._sign_and_store_sth()
            return self._sth_dict(row[0], bytes(row[1]), row[2], bytes(row[3]))

    def get_entry(self, index: int) -> bytes:
        with self._lock:
            row = self._db.execute("SELECT data FROM entries WHERE idx = ?", (index,)).fetchone()
            if row is None:
                raise IndexError(index)
            return bytes(row[0])

    def inclusion_proof(self, index: int, tree_size: int) -> list[bytes]:
        with self._lock:
            return self.tree.inclusion_proof(index, tree_size)

    def consistency_proof(self, first: int, second: int) -> list[bytes]:
        with self._lock:
            return self.tree.consistency_proof(first, second)

    def __len__(self):
        return len(self.tree)
