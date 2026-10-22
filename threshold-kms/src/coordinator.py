import asyncio
import os
import ssl

import httpx

from feldman_vss import FeldmanVSS, Q

CERTS_DIR = os.getenv("CERTS_DIR", "../certs")
CLUSTER_NODES = [f"https://localhost:{8000 + i}" for i in range(1, 6)]


def build_client_ssl_context() -> ssl.SSLContext:
    """Строгий mTLS-клиент: проверяем сервер по CA и предъявляем сертификат координатора."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{CERTS_DIR}/ca.crt")
    ctx.load_cert_chain(certfile=f"{CERTS_DIR}/coord.crt", keyfile=f"{CERTS_DIR}/coord.key")
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


async def distribute_key_vss(key_id: str, threshold: int, total_nodes: int) -> list[str]:
    """Раздаёт доли на все узлы. Если сохранили не все - откатывает и бросает RuntimeError.
    Возвращает коммитменты (публичные); секрет наружу не отдаётся."""
    vss = FeldmanVSS(threshold, total_nodes)
    secret = 0
    while not (0 < secret < Q):
        secret = int.from_bytes(os.urandom(32), "big")

    shares, commitments = vss.generate_shares_and_commitments(secret)
    del secret

    async with httpx.AsyncClient(verify=build_client_ssl_context(), timeout=10) as client:
        async def store(i: int, url: str) -> bool:
            payload = {
                "key_id": key_id,
                "share_x": shares[i][0],
                "share_y_hex": f"{shares[i][1]:064x}",  # всегда 64 символа
                "commitments": commitments,
            }
            try:
                resp = await client.post(f"{url}/api/v1/shares/store", json=payload)
                print(f"Узел {i + 1} сохранил долю: {resp.status_code}")
                return resp.status_code == 200
            except Exception as e:
                print(f"Ошибка на узле {i + 1}: {e}")
                return False

        results = await asyncio.gather(*(store(i, u) for i, u in enumerate(CLUSTER_NODES[:total_nodes])))

    if not all(results):
        print("❌ Раздача неполная, откатываю")
        await orchestrate_crypto_shredding(key_id, threshold, total_nodes)
        raise RuntimeError(f"Не удалось сохранить доли на всех узлах: {results}")
    return commitments


async def orchestrate_crypto_shredding(key_id: str, threshold: int, total_nodes: int) -> bool:
    """Опрашивает ВСЕ узлы (без раннего выхода по кворуму); успех = минимум n-k+1 подтверждений."""
    required = total_nodes - threshold + 1

    async with httpx.AsyncClient(verify=build_client_ssl_context(), timeout=10) as client:
        async def shred(url: str) -> bool:
            try:
                resp = await client.delete(f"{url}/api/v1/shares/{key_id}")
                return resp.status_code == 200
            except Exception as e:
                print(f"Ошибка удаления на {url}: {e}")
                return False

        results = await asyncio.gather(*(shred(u) for u in CLUSTER_NODES[:total_nodes]))

    shredded = sum(results)
    if shredded >= required:
        print(f"✅ Ключ {key_id} математически уничтожен ({shredded}/{total_nodes} узлов).")
        return True
    print(f"❌ Не удалось собрать 'Кворум смерти' ({shredded}/{required})")
    return False


if __name__ == "__main__":
    print("Координатор готов к работе.")
