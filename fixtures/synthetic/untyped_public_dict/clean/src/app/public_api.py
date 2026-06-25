from typing import TypedDict


class RoutePayload(TypedDict):
    route_id: str
    rank: int


def build_route_payload(route_id: str) -> RoutePayload:
    return {"route_id": route_id, "rank": 1}
