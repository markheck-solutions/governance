from .tickets import ticket_prefix


def route_key(route_id: str) -> str:
    return f"{ticket_prefix()}-{route_id}"
