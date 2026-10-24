"""Run the server:  python -m flashcards_teams

Settings come from environment variables; see flashcards_teams/app.py for the list.
"""

from __future__ import annotations

import logging
import os

import uvicorn

from .app import build_app, check_provider, load_settings, server_options


def main() -> None:
    settings = load_settings(os.environ)
    logging.basicConfig(level=settings.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Without sessions the SDK logs "Terminating session: None" after every request.
    logging.getLogger("mcp.server.streamable_http").setLevel(logging.WARNING)
    # The connection pool logs three INFO lines for every database call.
    logging.getLogger("psycopg.pool").setLevel(logging.WARNING)
    check_provider(settings)
    app = build_app(settings)
    try:
        uvicorn.run(app, **server_options(settings))
    finally:
        app.state.store.close()


if __name__ == "__main__":
    main()
