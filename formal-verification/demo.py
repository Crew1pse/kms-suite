import os, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(here, "src")]
from models import x3dh, healing_report

def show(m):
    print(f"\n{m.name}\n  минимальные наборы утечек, раскрывающие ключ сессии:")
    for c in sorted(m.minimal_cut_sets(), key=lambda c: (len(c), sorted(c))):
        print("   ", " + ".join(sorted(c)))

show(x3dh())
show(x3dh(with_opk=False))
print("\nForward secrecy при утечке ВСЕХ долгоживущих ключей (ik_a, ik_b, spk_b):")
print("  с одноразовым prekey: ключ", "РАСКРЫТ" if x3dh().broken_by({"ik_a","ik_b","spk_b"}) else "цел")
print("  без него:             ключ", "РАСКРЫТ" if x3dh(with_opk=False).broken_by({"ik_a","ik_b","spk_b"}) else "цел")
show(x3dh(omit=("DH1",)))
show(x3dh(pq=True))
print("\nDouble Ratchet: через сколько шагов после кражи состояния корневой ключ снова секретен")
for (t, p), h in sorted(healing_report(10).items())[:6]:
    print(f"  кража у {p} после сообщения {t}: ключ секретен с шага +{h}")
