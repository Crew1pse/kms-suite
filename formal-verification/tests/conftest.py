import os, sys
here = os.path.dirname(__file__)
for p in ("../src", "../../e2ee-messenger/src", "../../e2ee-messenger/tests"):
    sys.path.insert(0, os.path.normpath(os.path.join(here, p)))
