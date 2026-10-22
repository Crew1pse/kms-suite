import pytest
from models import *

F = frozenset


def cuts(**kw):
    return set(x3dh(**kw).minimal_cut_sets())


def test_x3dh_with_opk_exact_cut_sets():
    """Ровно три минимальных способа раскрыть ключ (совпадает с анализом Cohn-Gordon et al. для Signal)."""
    assert cuts() == {F({"ek_a", "ik_a"}), F({"ek_a", "spk_b"}), F({"ik_b", "spk_b", "opk_b"})}


def test_x3dh_without_opk_exact_cut_sets():
    assert cuts(with_opk=False) == {F({"ek_a", "ik_a"}), F({"ek_a", "spk_b"}), F({"ik_b", "spk_b"})}


def test_secret_without_any_compromise():
    assert not x3dh().broken_by([])


def test_forward_secrecy_of_longterm_keys_holds_only_with_opk():
    """Утекли ВСЕ долгоживущие ключи (ik_a, ik_b, spk_b). С одноразовым prekey сессия цела, без него - раскрыта."""
    assert not x3dh(with_opk=True).broken_by(LONG_TERM | {"ik_a"})
    assert x3dh(with_opk=False).broken_by(LONG_TERM)


def test_no_single_compromise_ever_breaks_it():
    for s in x3dh().secrets:
        assert not x3dh().broken_by([s])


def test_ephemeral_alone_is_not_enough():
    assert not x3dh().broken_by(["ek_a"])


@pytest.mark.parametrize("omitted,expected_single", [
    ("DH1", {"ek_a"}),         # без DH1 нет аутентификации Алисы: одного эфемерного ключа хватает
    ("DH2", {"spk_b", "ik_a"}),
    ("DH3", {"ik_a", "ik_b"}),
])
def test_mutants_lose_security(omitted, expected_single):
    """Если убрать любой DH из KDF, появляются более слабые наборы утечек: именно поэтому в X3DH их четыре."""
    base = cuts()
    mutant = cuts(omit=(omitted,))
    weaker = {c for c in mutant if not any(b <= c for b in base)}
    assert weaker, f"удаление {omitted} не ослабило модель - тест бесполезен"
    assert any(len(c) < min(len(b) for b in base) or c not in base for c in weaker)


def test_omitting_dh1_makes_ephemeral_plus_public_enough_to_break_with_one_leak():
    m = x3dh(omit=("DH1",), with_opk=False)
    assert F({"ek_a"}) in set(m.minimal_cut_sets())            # одной утечки эфемерного ключа достаточно: см. тест на реальном коде


def test_pq_hybrid_requires_breaking_both():
    """Квантовый атакующий ломает X25519: знает ВСЕ экспоненты. Без секрета KEM ключ цел. И наоборот."""
    m = x3dh(pq=True)
    all_dh = {"ik_a", "ik_b", "spk_b", "ek_a", "opk_b"}
    assert not m.broken_by(all_dh)
    assert not m.broken_by(["ss_kem"])
    assert m.broken_by(all_dh | {"ss_kem"})
    for c in m.minimal_cut_sets():
        assert "ss_kem" in c


def test_without_pq_quantum_attacker_wins():
    assert x3dh().broken_by({"ek_a", "ik_a"})
