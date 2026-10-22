import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from softtpm import SoftTPM, Manufacturer, sha, TpmError
from node_attest import NodeAttestor, BootPolicy, attest_node
from spire import SpireServer, AttestationError
from svid import make_csr, new_key, spiffe_id_of

vendor, srv = Manufacturer(), SpireServer("prod.example")
good = [(0, b"fw-1"), (4, b"kernel-ok")]
att = NodeAttestor(srv, [vendor.cert], BootPolicy((0, 4), {0: {sha(b"fw-1")}, 4: {sha(b"kernel-ok")}}))
def machine(events):
    t = SoftTPM(vendor)
    for p, d in events: t.measure(p, d)
    return t
print("1. Честный узел:", spiffe_id_of(attest_node(machine(good), att, make_csr(new_key()))))
for title, m in (("2. Руткит в ядре", machine([(0, b"fw-1"), (4, b"kernel-evil")])),
                 ("3. Программный TPM без подписи производителя", None)):
    try:
        t = m or (lambda x: [x.measure(p, d) for p, d in good] and x)(SoftTPM(Manufacturer("Evil")))
        attest_node(t, att, make_csr(new_key()))
    except (AttestationError, TpmError) as e: print(title + ":", e)
