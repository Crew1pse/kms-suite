"""Минимальный символьный движок Дулева-Яо с теорией Диффи-Хеллмана.

Термы:  ("n", имя) атом;  ("pub", e) = g^e;  ("exp", {e1,e2}) = g^(e1*e2) (общий DH-секрет);
        ("h", метка, (арг...)) односторонняя функция (KDF/хэш);  ("tup", (...)) кортеж.
Пассивный атакующий знает публичные значения и скомпрометированные секреты. Он выводит новое по правилам:
  анализ    - кортеж -> компоненты;
  DH        - знает экспоненту x и g^y  =>  знает g^(xy);
  синтез    - h(метка, арги) вычислим, если вычислимы все арги; g^x вычислим, если известен x.
Эквациональная теория: g^(xy) = g^(yx) (exp хранится как множество).
Сложность полиномиальна по размеру модели; перебор наборов компрометации - по подмножествам (модели маленькие)."""
from itertools import combinations


def N(x): return ("n", x)
def pub(e): return ("pub", e)
def exp_(*es): return ("exp", frozenset(es))
def h(label, *args): return ("h", label, tuple(args))
def tup(*a): return ("tup", tuple(a))


class Knowledge:
    def __init__(self, public_terms, exponent_names):
        self.exps = set(exponent_names)
        self.k = set()
        for t in public_terms:
            self.k.add(t)
        self._close()

    def learn(self, term):
        self.k.add(term)
        self._close()

    def _close(self):
        changed = True
        while changed:
            changed = False
            new = set()
            for t in self.k:
                if t[0] == "tup":
                    new.update(t[1])
            known_exps = {t[1] for t in self.k if t[0] == "n" and t[1] in self.exps}
            public_shares = {t[1] for t in self.k if t[0] == "pub"} | known_exps  # g^x вычислим из x
            for x in known_exps:
                new.add(pub(x))
                for y in public_shares:
                    if y != x:
                        new.add(exp_(x, y))
            if not new <= self.k:
                self.k |= new
                changed = True

    def derives(self, t) -> bool:
        if t in self.k:
            return True
        kind = t[0]
        if kind == "h":
            return all(self.derives(a) for a in t[2])
        if kind == "tup":
            return all(self.derives(a) for a in t[1])
        if kind == "pub":
            return N(t[1]) in self.k
        return False


class Model:
    """public - что видит сеть; secrets - имена, которые можно скомпрометировать; target - что должно остаться секретным."""

    def __init__(self, name, public, secrets, exponents, target, base_known=()):
        self.name, self.public, self.secrets = name, list(public), list(secrets)
        self.exponents, self.target, self.base_known = set(exponents), target, list(base_known)

    def broken_by(self, compromised) -> bool:
        k = Knowledge(self.public + self.base_known, self.exponents)
        for s in compromised:
            k.learn(N(s))
        return k.derives(self.target)

    def minimal_cut_sets(self) -> list[frozenset]:
        """Минимальные наборы утечек, при которых цель вычислима. Пустой набор в ответе = протокол сломан без утечек."""
        found: list[frozenset] = []
        for size in range(len(self.secrets) + 1):
            for combo in combinations(sorted(self.secrets), size):
                c = frozenset(combo)
                if any(f <= c for f in found):
                    continue
                if self.broken_by(c):
                    found.append(c)
        return found
