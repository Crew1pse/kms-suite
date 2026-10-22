"""Аудит операций узла в журнал прозрачности. Fail-closed: нет записи в журнал -> нет операции."""
import hashlib
import json
import os
import time

import httpx

AUDIT_URL = os.getenv("AUDIT_LOG_URL", "")
AUDIT_TOKEN = os.getenv("AUDIT_LOG_TOKEN", "")
AUDIT_CA = os.getenv("AUDIT_LOG_CA", "")
AUDIT_TIMEOUT = float(os.getenv("AUDIT_LOG_TIMEOUT", "3"))


class AuditUnavailable(Exception):
    pass


def build_event(node_id: int, op: str, key_id: str, peer_cn) -> bytes:
    """key_id в журнал попадает только как SHA-256: журнал публично читаем, идентификаторы ключей - нет."""
    return json.dumps({"v": 1, "ts": int(time.time()), "node_id": node_id, "op": op,
                       "key_sha256": hashlib.sha256(key_id.encode()).hexdigest(), "peer_cn": peer_cn},
                      sort_keys=True, separators=(",", ":")).encode()


async def http_sink(event: bytes) -> None:
    if not AUDIT_URL:
        return   # аудит выключен конфигурацией
    try:
        async with httpx.AsyncClient(verify=AUDIT_CA or True, timeout=AUDIT_TIMEOUT) as c:
            r = await c.post(f"{AUDIT_URL}/v1/entries", content=event,
                             headers={"Authorization": f"Bearer {AUDIT_TOKEN}"})
        if r.status_code != 200:
            raise AuditUnavailable(f"журнал ответил {r.status_code}")
    except AuditUnavailable:
        raise
    except Exception as e:
        raise AuditUnavailable(str(e)) from e
