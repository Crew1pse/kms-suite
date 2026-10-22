"""Auto-unseal через transit второго сервера (on-prem паттерн).
Порядок:  ./make_certs.sh && docker compose --profile auto up -d unsealer && python auto_unseal_demo.py
Скрипт сам запускает/перезапускает bao-auto через `docker compose`. Только stdlib.
"""
import base64, json, os, ssl, subprocess, sys, time, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
CTX = ssl.create_default_context(cafile=os.path.join(HERE, "tls/ca.crt"))
UNSEALER = "https://localhost:8210"
TARGET = "https://localhost:8220"
res = []


def call(addr, method, path, body=None, token=None, expect=(200, 204)):
    req = urllib.request.Request(f"{addr}/v1/{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    if token:
        req.add_header("X-Vault-Token", token)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=15) as r:
            raw, code = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, code = e.read(), e.code
    data = json.loads(raw) if raw else {}
    if expect and code not in expect:
        raise RuntimeError(f"{method} {addr}/{path} -> {code}: {data}")
    return code, data


def check(name, cond):
    res.append(bool(cond)); print(("PASS  " if cond else "FAIL  ") + name)


def dc(*args):
    subprocess.run(["docker", "compose", "--profile", "auto", "--profile", "auto-target", *args], cwd=HERE, check=True, capture_output=True)


def status(addr):
    try:
        return call(addr, "GET", "sys/seal-status", expect=None)[1]
    except Exception:
        return None


def wait(addr, pred, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        st = status(addr)
        if st is not None and pred(st):
            return st
        time.sleep(1)
    return status(addr)


# ---- 1. Unsealer: init + ручной unseal (единственное место, где нужны операторы) ----
wait(UNSEALER, lambda s: True, 30)
if status(UNSEALER) is None:
    sys.exit("Unsealer недоступен: docker compose --profile auto up -d unsealer")
if not status(UNSEALER)["initialized"]:
    _, init = call(UNSEALER, "PUT", "sys/init", {"secret_shares": 5, "secret_threshold": 3})
    keys, root = init["keys_base64"], init["root_token"]
    json.dump({"keys": keys, "root": root}, open(os.path.join(HERE, "data/unsealer-secrets.json"), "w"))
else:
    s = json.load(open(os.path.join(HERE, "data/unsealer-secrets.json")))
    keys, root = s["keys"], s["root"]
for k in keys[:3]:
    if status(UNSEALER)["sealed"]:
        call(UNSEALER, "PUT", "sys/unseal", {"key": k})
check("Unsealer распечатан вручную (3 из 5)", status(UNSEALER)["sealed"] is False)
time.sleep(2)

# ---- 2. Transit-ключ и узкая политика для целевого кластера ----
call(UNSEALER, "POST", "sys/mounts/transit", {"type": "transit"}, root, expect=(200, 204, 400))
call(UNSEALER, "POST", "transit/keys/autounseal", {"type": "aes256-gcm96"}, root)
call(UNSEALER, "PUT", "sys/policies/acl/autounseal", {"policy": """
path "transit/encrypt/autounseal" { capabilities = ["update"] }
path "transit/decrypt/autounseal" { capabilities = ["update"] }
"""}, root)
_, tok = call(UNSEALER, "POST", "auth/token/create",
              {"policies": ["autounseal"], "no_default_policy": True, "period": "24h", "renewable": True,
               "display_name": "bao-auto-seal"}, root)
seal_token = tok["auth"]["client_token"]

# ---- 3. Конфиг seal "transit" для цели ----
seal_hcl = f'''seal "transit" {{
  address         = "https://unsealer:8200"
  token           = "{seal_token}"
  key_name        = "autounseal"
  mount_path      = "transit/"
  tls_ca_cert     = "/openbao/tls/ca.crt"
  disable_renewal = "false"
}}
'''
path = os.path.join(HERE, "config/auto/seal.hcl")
open(path, "w").write(seal_hcl); os.chmod(path, 0o644)   # DEMO: в проде токен через секрет-менеджер/agent

# ---- 4. Старт цели, init с recovery-ключами ----
dc("up", "-d", "bao-auto")
st = wait(TARGET, lambda s: "initialized" in s, 60)
check("цель стартовала с seal type=transit", st and st.get("type") == "transit")
if not st["initialized"]:
    _, tinit = call(TARGET, "PUT", "sys/init", {"recovery_shares": 5, "recovery_threshold": 3})
    troot, rkeys = tinit["root_token"], tinit["recovery_keys_base64"]
    json.dump({"recovery": rkeys, "root": troot}, open(os.path.join(HERE, "data/auto-secrets.json"), "w"))
    check("выданы recovery-ключи, unseal-ключей нет", len(rkeys) == 5 and not tinit.get("keys"))
else:
    troot = json.load(open(os.path.join(HERE, "data/auto-secrets.json")))["root"]
st = wait(TARGET, lambda s: s["sealed"] is False, 60)
check("после init цель распечатана автоматически (без операторов)", st and st["sealed"] is False)

# ---- 5. Данные до рестарта ----
time.sleep(2)
call(TARGET, "POST", "sys/mounts/transit", {"type": "transit"}, troot, expect=(200, 204, 400))
call(TARGET, "POST", "transit/keys/tenant-a", {"type": "aes256-gcm96"}, troot, expect=(200, 204))
pt = base64.b64encode(os.urandom(32)).decode()
_, enc = call(TARGET, "POST", "transit/encrypt/tenant-a", {"plaintext": pt}, troot)

# ---- 6. Рестарт цели: поднимается сама ----
dc("restart", "bao-auto")
st = wait(TARGET, lambda s: s["sealed"] is False, 60)
check("после рестарта цель распечаталась сама", st and st["sealed"] is False)
_, dec = call(TARGET, "POST", "transit/decrypt/tenant-a", {"ciphertext": enc["data"]["ciphertext"]}, troot)
check("данные до рестарта расшифровываются", dec["data"]["plaintext"] == pt)

# ---- 7. Отказ Unsealer'а: цель остаётся запечатанной (fail-closed) ----
dc("stop", "unsealer"); dc("restart", "bao-auto")
time.sleep(15)
st = status(TARGET)
check("Unsealer недоступен -> цель остаётся sealed", st is not None and st["sealed"] is True)

# ---- 8. Unsealer вернулся, но сам запечатан ----
dc("start", "unsealer")
wait(UNSEALER, lambda s: "sealed" in s, 30)
check("Unsealer после рестарта запечатан (нужны операторы)", status(UNSEALER)["sealed"] is True)
for k in keys[:3]:
    if status(UNSEALER)["sealed"]:
        call(UNSEALER, "PUT", "sys/unseal", {"key": k})
time.sleep(2)
dc("restart", "bao-auto")   # перезапуск надёжнее, чем ждать повторной попытки сида
st = wait(TARGET, lambda s: s["sealed"] is False, 60)
check("Unsealer распечатан -> цель снова автоматически открыта", st and st["sealed"] is False)

print(f"\n{sum(res)}/{len(res)} passed")
sys.exit(0 if all(res) else 1)
