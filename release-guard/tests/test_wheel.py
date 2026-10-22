import os, subprocess, sys, time, zipfile, io
import pytest
from helpers import *
from wheel import *
from repro import ReproError
from sbom import SbomError


def pkgdir(tmp, extra=None):
    d = tmp / "pk"; (d / "mypkg").mkdir(parents=True)
    (d / "mypkg" / "__init__.py").write_text("VALUE = 42\n")
    (d / "mypkg" / "util.py").write_text("def f():\n    return 'ok'\n")
    for k, v in (extra or {}).items():
        (d / k).write_text(v)
    return str(d)


def test_wheel_is_byte_identical_across_builds_mtimes_and_dirs(tmp_path):
    a = pkgdir(tmp_path)
    w1 = build_wheel(a, "my-pkg", "1.0")
    os.utime(os.path.join(a, "mypkg", "util.py"), (12345, 12345)); time.sleep(0.01)
    assert build_wheel(a, "my-pkg", "1.0") == w1
    import shutil; shutil.copytree(a, str(tmp_path / "copy"))
    assert build_wheel(str(tmp_path / "copy"), "my-pkg", "1.0") == w1


def test_wheel_changes_with_content_and_metadata(tmp_path):
    a = pkgdir(tmp_path); base = build_wheel(a, "my-pkg", "1.0")
    assert build_wheel(a, "my-pkg", "1.1") != base
    assert build_wheel(a, "my-pkg", "1.0", ["x==1"]) != base
    open(os.path.join(a, "mypkg", "__init__.py"), "w").write("VALUE = 43\n")
    assert build_wheel(a, "my-pkg", "1.0") != base


def test_wheel_has_fixed_timestamps_and_record_last(tmp_path):
    data = build_wheel(pkgdir(tmp_path), "my-pkg", "1.0")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert {i.date_time for i in z.infolist()} == {(1980, 1, 1, 0, 0, 0)}
        assert z.namelist()[-1].endswith("RECORD")
        assert z.testzip() is None


def test_record_verifies_and_detects_tamper(tmp_path):
    data = build_wheel(pkgdir(tmp_path), "my-pkg", "1.0")
    verify_wheel_record(data)
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(buf, "w") as zout:
        for i in zin.infolist():
            c = zin.read(i.filename)
            zout.writestr(i, c.replace(b"VALUE = 42", b"VALUE = 99") if i.filename.endswith("__init__.py") else c)
    with pytest.raises(ReproError, match="хэш"):
        verify_wheel_record(buf.getvalue())


def test_extra_file_not_in_record_detected(tmp_path):
    data = build_wheel(pkgdir(tmp_path), "my-pkg", "1.0")
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(buf, "w") as zout:
        for i in zin.infolist():
            zout.writestr(i, zin.read(i.filename))
        zout.writestr("mypkg/backdoor.py", "import os")
    with pytest.raises(ReproError, match="RECORD"):
        verify_wheel_record(buf.getvalue())


def test_pip_installs_the_wheel_and_package_works(tmp_path):
    whl = tmp_path / wheel_filename("my-pkg", "1.0"); whl.write_bytes(build_wheel(pkgdir(tmp_path), "my-pkg", "1.0"))
    target = tmp_path / "site"
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-index", "--target", str(target), str(whl), "-q"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = subprocess.run([sys.executable, "-c", "import mypkg; from mypkg.util import f; print(mypkg.VALUE, f())"],
                         capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(target)})
    assert out.stdout.strip() == "42 ok"
    assert (target / "my_pkg-1.0.dist-info" / "METADATA").exists()


def test_symlink_and_empty_refused(tmp_path):
    a = pkgdir(tmp_path); os.symlink("/etc/passwd", os.path.join(a, "mypkg", "l"))
    with pytest.raises(ReproError):
        build_wheel(a, "my-pkg", "1.0")
    (tmp_path / "empty").mkdir()
    with pytest.raises(ReproError):
        build_wheel(str(tmp_path / "empty"), "x", "1")


# ---- как релизный артефакт ----
def test_wheel_release_end_to_end_with_rebuild(tmp_path):
    w = World(tmp_path); w.src = pkgdir(tmp_path)
    art, b = build_release(w.src, "my-pkg", "1.0", REQ, w.signers, w.log, kind="wheel")
    st = verify_release(art, b, w.policy, rebuild_src=w.src)
    assert st["subject"][0]["name"] == "my_pkg-1.0-py3-none-any.whl"
    verify_wheel_record(art)


def test_wheel_release_detects_source_change(tmp_path):
    w = World(tmp_path); w.src = pkgdir(tmp_path)
    art, b = build_release(w.src, "my-pkg", "1.0", REQ, w.signers, w.log, kind="wheel")
    open(os.path.join(w.src, "mypkg", "util.py"), "a").write("\nimport evil\n")
    with pytest.raises(ReleaseRejected, match="пересборка"):
        verify_release(art, b, w.policy, rebuild_src=w.src)


def test_record_line_format_has_no_padding_pep427():
    import hashlib, base64
    line = _record_line_for(b"hello")
    digest = base64.urlsafe_b64encode(hashlib.sha256(b"hello").digest()).decode()
    assert digest.endswith("=")                                   # у sha256 в base64 всегда один '='
    assert line == f"f.py,sha256={digest.rstrip('=')},5" and "=" not in line.split("sha256=")[1]


def _record_line_for(data):
    from wheel import _record_line
    return _record_line("f.py", data)


def test_record_referencing_missing_file_detected(tmp_path):
    data = build_wheel(pkgdir(tmp_path), "my-pkg", "1.0")
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as zin, zipfile.ZipFile(buf, "w") as zout:
        for i in zin.infolist():
            c = zin.read(i.filename)
            if i.filename.endswith("RECORD"):
                c = c.replace(b"\n", b"\nghost.py,sha256=AAAA,1\n", 1)
            zout.writestr(i, c)
    with pytest.raises(ReproError, match="отсутствующие"):
        verify_wheel_record(buf.getvalue())
