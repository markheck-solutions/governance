from .tickets import ticket_key


def route_key(route_id: str) -> str:
    return ticket_key(route_id)
