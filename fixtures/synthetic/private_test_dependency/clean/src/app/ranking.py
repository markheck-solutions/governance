from ._ranking import _rank_trunks


def rank_trunks(route_ids: list[str]) -> list[str]:
    return _rank_trunks(route_ids)
