"""Модели протоколов из ../e2ee-messenger в символьном виде."""
from symbolic import *

LONG_TERM = {"ik_a", "ik_b", "spk_b"}


def x3dh(with_opk=True, omit=(), pq=False, pq_secret_leakable=True) -> Model:
    """X3DH: sk = KDF(DH1||DH2||DH3[||DH4]). omit - какие DH убрать (мутанты). pq=True добавляет секрет ML-KEM."""
    exps = ["ik_a", "ik_b", "spk_b", "ek_a"] + (["opk_b"] if with_opk else [])
    dh = {"DH1": exp_("ik_a", "spk_b"), "DH2": exp_("ek_a", "ik_b"), "DH3": exp_("ek_a", "spk_b")}
    if with_opk:
        dh["DH4"] = exp_("ek_a", "opk_b")
    parts = [dh[k] for k in sorted(dh) if k not in omit]
    secrets = list(exps)
    if pq:
        parts.append(N("ss_kem"))
        secrets.append("ss_kem")                       # общий секрет KEM; утекает при взломе ML-KEM (или ключа декапсуляции)
    return Model(f"X3DH(opk={with_opk}, omit={sorted(omit)}, pq={pq})", [pub(e) for e in exps], secrets, exps,
                 h("sk", *parts))


def double_ratchet(steps=6, leak_party="B", leak_at=2) -> Model:
    """Корневая цепочка DR: rk_k = KDF(rk_{k-1}, DH(e_{k-1}, e_k)); e_0 = spk_b, e_1 = a1, e_2 = b1, e_3 = a2 ...
    Утечка состояния стороны в момент t: rk_t и все её приватные ratchet-ключи, созданные к моменту t.
    Цель - rk_{target}; см. healing_report()."""
    raise NotImplementedError("используйте healing_report")


def owner(i):
    """e_0 = SPK Боба; дальше ratchet-ключи чередуются: a1(Алиса), b1(Боб), a2, b2 ..."""
    return "B" if i == 0 else ("A" if i % 2 == 1 else "B")


def healing_report(max_steps=8):
    """Для каждого момента утечки t и каждой утёкшей стороны: на каком шаге корневой ключ снова недоступен атакующему.
    Утечка = (rk_t, приватные ключи e_j стороны для j <= t+1, принадлежащие ей: она уже создала e_{t+1}, если её очередь)."""
    out = {}
    for t in range(1, max_steps - 3):
        for party in ("A", "B"):
            exps = [f"e{i}" for i in range(max_steps + 1)]
            public = [pub(e) for e in exps]
            rk = {0: N("sk")}
            for k in range(1, max_steps + 1):
                rk[k] = h("rk", rk[k - 1], exp_(f"e{k-1}", f"e{k}"))
            m = Knowledge(public, exps)
            m.learn(rk[t])
            for j in range(0, t + 2):
                if owner(j) == party:
                    m.learn(N(f"e{j}"))
            first_safe = next((k for k in range(t + 1, max_steps + 1) if not m.derives(rk[k])), None)
            out[(t, party)] = first_safe - t if first_safe else None
    return out
