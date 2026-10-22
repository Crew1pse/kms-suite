import os
import re
import ssl
import asyncio
from contextlib import asynccontextmanager
from concurrent.futures import ProcessPoolExecutor

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol
from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel

from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base, Mapped, mapped_column

from feldman_vss import FeldmanVSS, Q
from audit_client import AuditUnavailable, build_event, http_sink

NODE_ID = int(os.getenv("NODE_ID", "1"))
NODE_PORT = int(os.getenv("NODE_PORT", "8001"))
NODE_HOST = os.getenv("NODE_HOST", "127.0.0.1")
K_THRESHOLD = int(os.getenv("K_THRESHOLD", "3"))
MAX_COMMITMENTS = 10
COORDINATOR_CN = os.getenv("COORDINATOR_CN", "kms-coordinator")
# Если задан, авторизация идёт по SPIFFE ID (URI SAN) вместо CN: см. workload-identity/.
COORDINATOR_SPIFFE_ID = os.getenv("COORDINATOR_SPIFFE_ID") or None

if not (1 <= K_THRESHOLD <= MAX_COMMITMENTS):
    raise SystemExit(f"K_THRESHOLD must be in 1..{MAX_COMMITMENTS}")

IN_DOCKER = bool(os.getenv("DOCKER"))
DB_DIR = "/app/data" if IN_DOCKER else "./data"
CERTS_DIR = os.getenv("CERTS_DIR", "/app/certs" if IN_DOCKER else "../certs")
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = f"sqlite+aiosqlite:///{DB_DIR}/node_{NODE_ID}.db"

engine = create_async_engine(DB_PATH, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)
Base = declarative_base()


# PRAGMA secure_delete действует на соединение, а не на файл БД -> ставим на каждое новое.
@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA secure_delete = ON")
    cursor.close()


class VaultRecord(Base):
    __tablename__ = "vault_shares"
    key_id: Mapped[str] = mapped_column(primary_key=True)
    share_x: Mapped[int] = mapped_column(nullable=True)
    share_y_hex: Mapped[str] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(default="ACTIVE")



@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    app.state.cpu_pool = ProcessPoolExecutor(max_workers=2)   # на каждый запуск приложения свой пул
    yield
    app.state.cpu_pool.shutdown(wait=False, cancel_futures=True)
    await engine.dispose()


app = FastAPI(title=f"Threshold Node {NODE_ID}", lifespan=lifespan)


# ---------- Авторизация по CN клиентского сертификата ----------

def require_coordinator(request: Request) -> None:
    """Fail-closed: пускаем только клиента с CN == COORDINATOR_CN.
    Соседние узлы (CN=kms-node-*) и любой другой CN получают 403."""
    if COORDINATOR_SPIFFE_ID is not None:
        # режим SPIFFE: единственный критерий - ровно один URI SAN, равный ожидаемому ID
        if request.scope.get("kms_peer_spiffe") != COORDINATOR_SPIFFE_ID:
            raise HTTPException(status_code=403, detail="Forbidden")
        return
    if request.scope.get("kms_peer_cn") != COORDINATOR_CN:
        raise HTTPException(status_code=403, detail="Forbidden")


class MtlsH11Protocol(H11Protocol):
    """uvicorn не кладёт сертификат клиента в ASGI scope (scope["client"] - это только IP:порт),
    поэтому CN берём из TLS-сокета сами."""

    def _peer_cn(self):
        ssl_obj = self.transport.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj is not None else None
        for rdn in (cert or {}).get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    return value
        return None

    def _peer_spiffe(self):
        ssl_obj = self.transport.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert() if ssl_obj is not None else None
        uris = [v for k, v in (cert or {}).get("subjectAltName", ()) if k == "URI"]
        return uris[0] if len(uris) == 1 else None      # 0 или >1 URI SAN -> нет идентичности (fail-closed)

    def handle_events(self) -> None:
        super().handle_events()
        # scope создаётся внутри handle_events, а ASGI-задача стартует только после возврата
        # в event loop -> успеваем проставить CN. Нет CN -> require_coordinator откажет.
        self.scope["kms_peer_cn"] = self._peer_cn()
        self.scope["kms_peer_spiffe"] = self._peer_spiffe()


# ---------- Аудит (write-ahead, fail-closed) ----------

audit_sink = http_sink   # подменяется в тестах


async def audit(request: Request, op: str, key_id: str) -> None:
    """Запись намерения в журнал прозрачности ДО выполнения операции. Нет записи -> 503, состояние не меняется."""
    try:
        await audit_sink(build_event(NODE_ID, op, key_id, request.scope.get("kms_peer_cn")))
    except AuditUnavailable:
        raise HTTPException(status_code=503, detail="audit log unavailable")


# ---------- API ----------

HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SharePayload(BaseModel):
    key_id: str
    share_x: int
    share_y_hex: str
    commitments: list[str]


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


@app.post("/api/v1/shares/store", dependencies=[Depends(require_coordinator)])
async def store_share(request: Request, payload: SharePayload, db: AsyncSession = Depends(get_db)):
    await audit(request, "store", payload.key_id)
    if payload.share_x != NODE_ID:
        raise HTTPException(status_code=400, detail="share_x must equal NODE_ID")
    if not HEX64.match(payload.share_y_hex):
        raise HTTPException(status_code=400, detail="share_y_hex must be 64 lowercase hex chars")
    share_y_int = int(payload.share_y_hex, 16)
    if not (0 < share_y_int < Q):
        raise HTTPException(status_code=400, detail="share_y out of range")
    # commitments обязательны, длина строго K (и тем самым <= MAX_COMMITMENTS) - защита от CPU-DoS
    if len(payload.commitments) != K_THRESHOLD:
        raise HTTPException(status_code=400, detail=f"exactly {K_THRESHOLD} commitments required")
    if any(len(c) != 66 for c in payload.commitments):
        raise HTTPException(status_code=400, detail="malformed commitment")

    # verify_share сам возвращает False на любой мусор; прочие исключения (сбой пула) - это 500, а не вина клиента
    is_valid = await asyncio.get_running_loop().run_in_executor(
        request.app.state.cpu_pool, FeldmanVSS.verify_share, payload.share_x, share_y_int, payload.commitments
    )
    if not is_valid:
        raise HTTPException(status_code=400, detail="VSS verification failed")

    # Прямой INSERT: уникальность гарантирует PRIMARY KEY, гонки SELECT->INSERT нет.
    db.add(VaultRecord(key_id=payload.key_id, share_x=payload.share_x,
                       share_y_hex=payload.share_y_hex, status="ACTIVE"))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Ключ уже существует")
    return {"status": "stored", "node_id": NODE_ID}


@app.get("/api/v1/shares/retrieve/{key_id}", dependencies=[Depends(require_coordinator)])
async def retrieve_share(request: Request, key_id: str, db: AsyncSession = Depends(get_db)):
    await audit(request, "retrieve", key_id)
    record = (await db.execute(select(VaultRecord).where(VaultRecord.key_id == key_id))).scalars().first()
    if not record:
        raise HTTPException(status_code=404, detail="Доля не найдена")
    if record.status == "SHREDDED":
        raise HTTPException(status_code=410, detail="Ключ уничтожен")
    return {"node_id": NODE_ID, "share_x": record.share_x, "share_y_hex": record.share_y_hex}


@app.delete("/api/v1/shares/{key_id}", dependencies=[Depends(require_coordinator)])
async def shred_share(request: Request, key_id: str, db: AsyncSession = Depends(get_db)):
    await audit(request, "shred", key_id)
    record = (await db.execute(select(VaultRecord).where(VaultRecord.key_id == key_id))).scalars().first()

    if not record:
        db.add(VaultRecord(key_id=key_id, status="SHREDDED"))
        try:
            await db.commit()
        except IntegrityError:  # параллельный запрос успел раньше -> повторяем как обычный shred
            await db.rollback()
            return await shred_share(request, key_id, db)
        return {"status": "shredded", "message": "Tombstone created"}

    if record.status == "SHREDDED":
        return {"status": "already_shredded"}

    # Ручной memset по id()+32 удалён: он портил кучу CPython и ничего не стирал.
    # Затирание на диске: UPDATE поверх + secure_delete=ON на каждом соединении.
    record.share_y_hex = None
    record.share_x = None
    record.status = "SHREDDED"
    await db.commit()
    return {"status": "shredded"}


if __name__ == "__main__":
    # Fail-closed: нет сертификатов / ошибка конфигурации -> процесс падает, HTTP-фолбэка нет.
    uvicorn.run(
        app,
        host=NODE_HOST,
        port=NODE_PORT,
        http=MtlsH11Protocol,
        ssl_keyfile=f"{CERTS_DIR}/node.key",
        ssl_certfile=f"{CERTS_DIR}/node.crt",
        ssl_ca_certs=f"{CERTS_DIR}/ca.crt",
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
