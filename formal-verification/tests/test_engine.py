from symbolic import *


def kn(public, exps, leaked=()):
    k = Knowledge(public, exps)
    for s in leaked: k.learn(N(s))
    return k


def test_dh_commutative_and_needs_one_exponent():
    pubs = [pub("x"), pub("y")]
    assert not kn(pubs, ["x", "y"]).derives(exp_("x", "y"))
    assert kn(pubs, ["x", "y"], ["x"]).derives(exp_("y", "x"))
    assert kn(pubs, ["x", "y"], ["y"]).derives(exp_("x", "y"))


def test_passive_attacker_cannot_get_dh_from_publics_alone():
    assert not kn([pub("x"), pub("y"), pub("z")], "xyz").derives(exp_("x", "z"))


def test_hash_needs_all_arguments():
    t = h("kdf", exp_("x", "y"), exp_("y", "z"))
    pubs = [pub("x"), pub("y"), pub("z")]
    assert not kn(pubs, "xyz", ["x"]).derives(t)         # только DH(x,y)
    assert kn(pubs, "xyz", ["y"]).derives(t)             # y входит в оба DH
    assert not kn(pubs, "xyz", ["z"]).derives(t)


def test_hash_is_one_way():
    k = kn([h("kdf", N("s"))], [])
    assert not k.derives(N("s"))


def test_tuple_analysis():
    assert kn([tup(N("a"), N("b"))], []).derives(N("b"))


def test_minimal_cut_sets_are_minimal_and_complete():
    m = Model("t", [pub("a"), pub("b")], ["a", "b"], ["a", "b"], exp_("a", "b"))
    assert m.minimal_cut_sets() == [frozenset({"a"}), frozenset({"b"})]
    m2 = Model("t", [], ["a", "b"], [], tup(N("a"), N("b")))
    assert m2.minimal_cut_sets() == [frozenset({"a", "b"})]
    m3 = Model("t", [tup(N("a"))], ["a"], [], N("a"))
    assert m3.minimal_cut_sets() == [frozenset()]        # сломан без утечек


def test_public_share_of_unknown_exponent_not_derivable_but_known_exponent_gives_it():
    k = kn([], ["x"])
    assert not k.derives(pub("x"))
    k.learn(N("x"))
    assert k.derives(pub("x"))
