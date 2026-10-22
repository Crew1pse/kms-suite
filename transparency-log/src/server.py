"""HTTP API журнала. Запись - только по Bearer-токену (в проде: mTLS-клиент); чтение открыто."""
import base64
import hmac
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException, Header, Query, Request

from tlog import TransparencyLog

MAX_ENTRY = 64 * 1024


def load_or_create_key(path: str) -> Ed25519PrivateKey:
    if os.path.exists(path):
        return serialization.load_pem_private_key(open(path, "rb").read(), password=None)
    key = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return key


def create_app(log: TransparencyLog, append_token: str) -> FastAPI:
    if not append_token:
        raise ValueError("append_token обязателен")
    app = FastAPI(title="Transparency Log")

    @app.post("/v1/entries")
    async def add_entry(request: Request, authorization: str = Header(default="")):
        if not hmac.compare_digest(authorization, f"Bearer {append_token}"):
            raise HTTPException(401, "unauthorized")
        body = await request.body()
        if not body or len(body) > MAX_ENTRY:
            raise HTTPException(400, f"entry must be 1..{MAX_ENTRY} bytes")
        index, sth = log.append(body)
        return {"index": index, "sth": sth}

    @app.get("/v1/sth")
    def get_sth():
        return log.latest_sth()

    @app.get("/v1/pubkey")
    def get_pubkey():   # справочно; доверять нужно ключу, закреплённому у монитора заранее
        raw = log.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"alg": "ed25519", "public_key": raw.hex()}

    @app.get("/v1/entries/{index}")
    def get_entry(index: int):
        try:
            data = log.get_entry(index)
        except IndexError:
            raise HTTPException(404, "no such entry")
        return {"index": index, "data": base64.b64encode(data).decode()}

    @app.get("/v1/proof/inclusion")
    def inclusion(index: int = Query(ge=0), tree_size: int = Query(ge=1)):
        if tree_size > len(log) or index >= tree_size:
            raise HTTPException(400, "bad index/tree_size")
        return {"leaf_index": index, "tree_size": tree_size,
                "audit_path": [h.hex() for h in log.inclusion_proof(index, tree_size)]}

    @app.get("/v1/proof/consistency")
    def consistency(first: int = Query(ge=1), second: int = Query(ge=1)):
        if not (first <= second <= len(log)):
            raise HTTPException(400, "need 1 <= first <= second <= tree_size")
        return {"first": first, "second": second,
                "consistency_path": [h.hex() for h in log.consistency_proof(first, second)]}

    return app


def main():  # pragma: no cover
    import uvicorn
    db = os.getenv("TLOG_DB", "tlog.db")
    log = TransparencyLog(db, load_or_create_key(os.getenv("TLOG_KEY", "tlog_ed25519.pem")))
    uvicorn.run(create_app(log, os.environ["TLOG_APPEND_TOKEN"]), host=os.getenv("TLOG_HOST", "127.0.0.1"),
                port=int(os.getenv("TLOG_PORT", "9000")))


if __name__ == "__main__":
    main()
