"""Детерминированный tar.gz: одинаковое дерево -> побайтно одинаковый архив, на любой машине и в любое время."""
import gzip
import hashlib
import io
import os
import tarfile


class ReproError(Exception): pass


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def deterministic_targz(src_dir: str, prefix: str = "") -> bytes:
    files = []
    for root, dirs, names in os.walk(src_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for n in sorted(names):
            if n.endswith(".pyc"):
                continue
            full = os.path.join(root, n)
            if os.path.islink(full):
                raise ReproError(f"символические ссылки не допускаются: {full}")
            files.append((os.path.relpath(full, src_dir).replace(os.sep, "/"), full))
    files.sort()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, filename="", compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for rel, full in files:
                data = open(full, "rb").read()
                ti = tarfile.TarInfo(f"{prefix}{rel}")
                ti.size, ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0, 0, "", ""
                ti.mode = 0o755 if os.access(full, os.X_OK) and os.stat(full).st_mode & 0o111 else 0o644
                tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()
