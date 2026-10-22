"""PoC: как логика Threshold KMS ложится на OpenBao/Vault. Только stdlib, работает с обоими (одинаковый API).
Запуск:  ./make_certs.sh && docker compose --profile manual up -d bao-1 && python demo.py
"""
import base64, json, os, ssl, sys, time, urllib.request, urllib.error

ADDR = os.getenv("BAO_ADDR", "https://localhost:8200")
CA = os.getenv("BAO_CACERT", "tls/ca.crt")
AUDIT = os.getenv("BAO_AUDIT_FILE_HOST", "audit/audit.log")
CTX = ssl.create_default_context(cafile=CA)
ok_all = []


def call(method, path, body=None, token=None, expect=(200, 204)):
    req = urllib.request.Request(f"{ADDR}/v1/{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("X-Vault-Token", token)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
            raw = r.read(); code = r.status
    except urllib.error.HTTPError as e:
        raw = e.read(); code = e.code
    data = json.loads(raw) if raw else {}
    if expect and code not in expect:
        raise RuntimeError(f"{method} {path} -> {code}: {data}")
    return code, data


def check(name, cond):
    ok_all.append(bool(cond)); print(("PASS  " if cond else "FAIL  ") + name)


def b64(b): return base64.b64encode(b).decode()


# 1. Init: мастер-ключ режется по Шамиру 5/3 (то, что мы писали руками)
for _ in range(30):
    try:
        code, st = call("GET", "sys/init", expect=None); break
    except Exception:
        time.sleep(1)
if st.get("initialized"):
    sys.exit("Уже инициализирован: очистите ./data и перезапустите контейнер для чистого прогона.")
_, init = call("PUT", "sys/init", {"secret_shares": 5, "secret_threshold": 3})
keys, root = init["keys_base64"], init["root_token"]
check("init: 5 unseal-ключей выдано", len(keys) == 5)

# 2. Unseal: 2 ключа - всё ещё sealed, 3-й открывает
for i in (0, 1):
    _, s = call("PUT", "sys/unseal", {"key": keys[i]})
check("после 2 из 5 ключей: sealed=True (k-1 долей бесполезны)", s["sealed"] is True)
_, s = call("PUT", "sys/unseal", {"key": keys[2]})
check("после 3-го ключа: sealed=False", s["sealed"] is False)
time.sleep(2)  # дать raft выбрать лидера

# 3. Audit, transit, ключи двух арендаторов
call("PUT", "sys/audit/file", {"type": "file", "options": {"file_path": "/openbao/logs/audit.log"}}, root)
call("POST", "sys/mounts/transit", {"type": "transit"}, root)
for t in ("tenant-a", "tenant-b"):
    call("POST", f"transit/keys/{t}", {"type": "aes256-gcm96"}, root)  # exportable=false по умолчанию
_, k = call("GET", "transit/keys/tenant-a", token=root)
check("ключ не экспортируемый", k["data"]["exportable"] is False)

# 4. RBAC: политика только на encrypt/decrypt/datakey одного ключа + AppRole
call("PUT", "sys/policies/acl/app-a", {"policy": """
path "transit/encrypt/tenant-a"            { capabilities = ["update"] }
path "transit/decrypt/tenant-a"            { capabilities = ["update"] }
path "transit/datakey/wrapped/tenant-a"    { capabilities = ["update"] }
"""}, root)
call("POST", "sys/auth/approle", {"type": "approle"}, root)
call("POST", "auth/approle/role/app-a", {"token_policies": "app-a", "token_ttl": "5m"}, root)
_, r = call("GET", "auth/approle/role/app-a/role-id", token=root)
_, sid = call("POST", "auth/approle/role/app-a/secret-id", token=root)
_, login = call("POST", "auth/approle/login", {"role_id": r["data"]["role_id"], "secret_id": sid["data"]["secret_id"]})
app = login["auth"]["client_token"]

# 5. Envelope encryption: микросервис не видит KEK
_, dk = call("POST", "transit/datakey/wrapped/tenant-a", {}, app)
wrapped = dk["data"]["ciphertext"]
check("datakey/wrapped: сервис получил только обёрнутый DEK (plaintext нет)", "plaintext" not in dk["data"])
dek = os.urandom(32)
_, enc = call("POST", "transit/encrypt/tenant-a", {"plaintext": b64(dek)}, app)
_, dec = call("POST", "transit/decrypt/tenant-a", {"ciphertext": enc["data"]["ciphertext"]}, app)
check("encrypt/decrypt DEK круговым путём", base64.b64decode(dec["data"]["plaintext"]) == dek)
print("NOTE  decrypt вернул DEK открытым текстом: он оказался в RAM сервиса (KEK при этом не покидал OpenBao)")

# 6. Негативные проверки RBAC
c, _ = call("POST", "transit/decrypt/tenant-b", {"ciphertext": enc["data"]["ciphertext"]}, app, expect=None)
check("app-a не может использовать ключ tenant-b (403)", c == 403)
c, _ = call("DELETE", "transit/keys/tenant-a", None, app, expect=None)
check("app-a не может удалить ключ (403)", c == 403)
c, _ = call("GET", "transit/keys/tenant-a", None, app, expect=None)
check("app-a не может читать метаданные ключа (403)", c == 403)

# 7. Crypto-shredding: удалить ключ арендатора
c, _ = call("DELETE", "transit/keys/tenant-a", None, root, expect=None)
check("удаление без deletion_allowed запрещено", c in (400, 403))
call("POST", "transit/keys/tenant-a/config", {"deletion_allowed": True}, root)
call("DELETE", "transit/keys/tenant-a", None, root)
c, body = call("POST", "transit/decrypt/tenant-a", {"ciphertext": enc["data"]["ciphertext"]}, app, expect=None)
check("после удаления ключа расшифровка невозможна", c != 200)
check("tenant-b не затронут (ключ жив)", call("GET", "transit/keys/tenant-b", token=root)[0] == 200)

# 8. Audit
time.sleep(1)
if os.path.exists(AUDIT):
    raw = open(AUDIT).read()
    check("audit: операции записаны", raw.count('"type":"request"') >= 10)
    check("audit: DEK в открытом виде не попал в лог", b64(dek) not in raw and dek.hex() not in raw)
else:
    print(f"SKIP  audit: файл {AUDIT} не найден на хосте")

print(f"\n{sum(ok_all)}/{len(ok_all)} passed")
sys.exit(0 if all(ok_all) else 1)
