import os, sys
here = os.path.dirname(__file__)
for p in ("../src", "../../transparency-log/src", "../../threshold-signing/src"):
    sys.path.insert(0, os.path.normpath(os.path.join(here, p)))
