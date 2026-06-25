from app._ranking import _rank_trunks


def test_private_ranker() -> None:
    assert _rank_trunks(["B", "A"]) == ["A", "B"]
