import os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# node.py читает окружение при импорте: изолируем БД во временной папке
_tmp = tempfile.mkdtemp(prefix="kms-test-")
os.chdir(_tmp)
os.environ.setdefault("NODE_ID", "1")
os.environ.setdefault("K_THRESHOLD", "3")
