from .routes import route_key


def ticket_key(route_id: str) -> str:
    return f"TICKET-{route_key(route_id)}"
