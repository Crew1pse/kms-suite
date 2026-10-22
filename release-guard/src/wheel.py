"""Детерминированный wheel (PEP 427): побайтно одинаковый на любой машине. Только чистый Python (py3-none-any)."""
import base64
import hashlib
import io
import os
import re
import zipfile

from repro import ReproError

_FIXED_DATE = (1980, 1, 1, 0, 0, 0)         # минимум, допустимый в ZIP: никаких mtime сборочной машины


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name)


def _record_line(path: str, data: bytes) -> str:
    h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{path},sha256={h},{len(data)}"


def wheel_filename(name: str, version: str) -> str:
    return f"{_norm(name)}-{version}-py3-none-any.whl"


def build_wheel(src_dir: str, name: str, version: str, requires: list[str] | None = None) -> bytes:
    """src_dir содержит пакеты верхнего уровня (каталоги с __init__.py или модули .py)."""
    dist = f"{_norm(name)}-{version}.dist-info"
    files: dict[str, bytes] = {}
    for root, dirs, names in os.walk(src_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for n in sorted(names):
            full = os.path.join(root, n)
            if os.path.islink(full):
                raise ReproError(f"символические ссылки не допускаются: {full}")
            if n.endswith(".pyc"):
                continue
            files[os.path.relpath(full, src_dir).replace(os.sep, "/")] = open(full, "rb").read()
    if not files:
        raise ReproError("пустой пакет")
    meta = ["Metadata-Version: 2.1", f"Name: {_norm(name)}", f"Version: {version}"] + [f"Requires-Dist: {r}" for r in (requires or [])]
    files[f"{dist}/METADATA"] = ("\n".join(meta) + "\n").encode()
    files[f"{dist}/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: release-guard\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    record = [_record_line(p, d) for p, d in sorted(files.items())] + [f"{dist}/RECORD,,"]
    files[f"{dist}/RECORD"] = ("\n".join(record) + "\n").encode()
    order = sorted(p for p in files if not p.startswith(dist + "/")) + sorted(p for p in files if p.startswith(dist + "/") and not p.endswith("RECORD")) + [f"{dist}/RECORD"]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in order:
            zi = zipfile.ZipInfo(p, _FIXED_DATE)
            zi.external_attr = 0o644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.create_system = 3
            z.writestr(zi, files[p])
    return buf.getvalue()


def verify_wheel_record(data: bytes) -> None:
    """Каждый файл в wheel обязан совпадать с хэшем из RECORD, лишних файлов нет."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        rec = [n for n in z.namelist() if n.endswith(".dist-info/RECORD")]
        if len(rec) != 1:
            raise ReproError("в wheel должен быть ровно один RECORD")
        listed = {}
        for line in z.read(rec[0]).decode().splitlines():
            path, h, size = line.split(",")
            listed[path] = (h, size)
        for n in z.namelist():
            if n == rec[0]:
                continue
            if n not in listed:
                raise ReproError(f"файл {n} отсутствует в RECORD")
            if _record_line(n, z.read(n)).split(",", 1)[1] != ",".join(listed[n]):
                raise ReproError(f"хэш {n} не совпадает с RECORD")
        if set(listed) - set(z.namelist()):
            raise ReproError("RECORD ссылается на отсутствующие файлы")
