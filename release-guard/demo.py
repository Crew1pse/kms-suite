import os, sys, tempfile, dataclasses
here = os.path.dirname(os.path.abspath(__file__))
for p in ("src", "../transparency-log/src"):
    sys.path.insert(0, os.path.normpath(os.path.join(here, p)))
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tlog import TransparencyLog
from guard import build_release, verify_release, Policy, ReleaseRejected

raw = lambda k: k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
tmp = tempfile.mkdtemp()
src = os.path.join(tmp, "src"); os.makedirs(src)
open(os.path.join(src, "app.py"), "w").write("print('release')\n")
key, logkey = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
log = TransparencyLog(os.path.join(tmp, "log.db"), logkey)
art, bundle = build_release(src, "app", "1.0", "cryptography==50.0.2\n", [("release-key", key.sign)], log)
policy = Policy({"release-key": raw(key)}, 1, raw(logkey), {"https://example.invalid/builder/1"})
print("1. Релиз собран, подписан, записан в журнал (индекс %d)" % bundle.log["index"])
verify_release(art, bundle, policy, rebuild_src=src); print("2. Проверка + независимая пересборка: OK")
try: verify_release(art + b"\0", bundle, policy)
except ReleaseRejected as e: print("3. Подменённый артефакт:", e)
open(os.path.join(src, "app.py"), "a").write("import evil\n")
try: verify_release(art, bundle, policy, rebuild_src=src)
except ReleaseRejected as e: print("4. Исходники изменены после подписи:", e)
policy.blocked_components = {("cryptography", "50.0.2")}
try: verify_release(art, bundle, policy)
except ReleaseRejected as e: print("5. Уязвимый компонент в SBOM:", e)
