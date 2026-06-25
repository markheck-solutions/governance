from app import rank_trunks


def test_public_ranker() -> None:
    assert rank_trunks(["B", "A"]) == ["A", "B"]
