"""The deployable app: settings checked before anything starts, the MCP endpoint
answering only what it must, and server limits suited to free-tier hosting.

Settings come from environment variables. Only FLASHCARDS_DATABASE_URL is a secret
(it holds the database password); tokens are checked with the identity provider's
public keys.

  FLASHCARDS_ISSUER        the identity provider's issuer, copied exactly from its metadata
  FLASHCARDS_JWKS_URL      where the provider publishes its public signing keys (jwks_uri);
                           must be on the issuer's host
  FLASHCARDS_RESOURCE_URL  this server's MCP URL, exactly as users enter it in Claude and as
                           registered with the provider, e.g. https://example.onrender.com/mcp
  FLASHCARDS_SCOPES        optional: scopes every token must carry, e.g. "flashcards"
  FLASHCARDS_DATABASE_URL  Postgres connection URL (secret), e.g. from Neon; required on Render.
                           A remote database must use sslmode=require or stricter
  FLASHCARDS_DB            optional, local use only: SQLite file (default data/cards.db);
                           set this or FLASHCARDS_DATABASE_URL, not both
  FLASHCARDS_ALLOWED_ORIGINS  optional: other web origins whose requests are accepted, e.g.
                           "https://claude.ai" (requests without an Origin header always are)
  HOST, PORT               optional: where to listen (default 127.0.0.1 and 8000;
                           0.0.0.0 on Render, which sets RENDER=true)
  LOG_LEVEL                optional: DEBUG, INFO (default), WARNING or ERROR
"""

from __future__ import annotations

import http.client
import json
import logging
import re
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, ValidationError
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .server import create_server
from .store import CardStore, PostgresCardStore, SqliteCardStore, StoreUnavailableError
from .verifier import USER_AGENT, JwtTokenVerifier

logger = logging.getLogger(__name__)

LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
# Sign-in and refresh scopes belong to the identity provider, not to this server.
# Claude adds offline_access itself when the provider offers it.
NOT_RESOURCE_SCOPES = {"offline_access", "openid", "profile", "email"}
SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")  # RFC 6749 scope-token
# Characters RFC 3986 never allows unencoded in a URL, plus the single quote. Seeing one
# usually means a value was copied with some of the JSON around it.
NOT_IN_URLS = frozenset("\"'<>\\^`{|}")
# Render's edge reuses connections to the app for up to 75 s; closing them sooner causes 502s.
KEEP_ALIVE_SECONDS = 120
# Most simultaneous connections; beyond this new ones get 503 instead of the instance
# running out of memory.
MAX_CONNECTIONS = 400
# One process: the rate limiter and the database pool live in it. Written out because
# uvicorn otherwise reads WEB_CONCURRENCY, which Render sets, and exits at startup when
# that is above 1 and the app is passed as an object.
WORKERS = 1


class ConfigError(SystemExit):
    """Missing or invalid settings. Stops the server with a readable message."""


class _Url(BaseModel):
    # Same parsing as the SDK's AuthSettings, so "standard form" here means what the
    # metadata will show.
    model_config = ConfigDict(url_preserve_empty_path=True)
    url: AnyHttpUrl


@dataclass(frozen=True)
class Settings:
    issuer: str
    jwks_url: str
    resource_url: str
    scopes: list[str]
    db_path: Path | None
    host: str
    port: int
    log_level: str
    on_render: bool
    allowed_origins: list[str] = field(default_factory=list)
    # Holds the password: never shown, not even in repr() or error messages.
    database_url: str | None = field(default=None, repr=False)


def _setting(env: Mapping[str, str], name: str) -> str | None:
    """A setting without the spaces and line breaks around it (copy buttons tend to add a
    line break, and Render's multi-line value box keeps it), or None when it isn't set."""
    value = env.get(name)
    return None if value is None else value.strip()


def _url(env: Mapping[str, str], name: str, errors: list[str]) -> str:
    """A URL in its standard form: https (plain http only for this machine), lower-case
    scheme and host, no default port, no user name, query or fragment. The token and
    Host checks compare strings exactly, so any other spelling would refuse everyone
    while the metadata (which the SDK normalizes) looked fine."""
    value = _setting(env, name) or ""
    if not value:
        errors.append(f"{name} is missing")
        return value
    stray = next((c for c in value if c in NOT_IN_URLS), None)
    if stray:
        # Checked first: JSON copied from a formatted view has spaces too, and the standard
        # form would percent-encode the character, a suggestion that would only mislead.
        errors.append(
            f"{name} contains {stray!r}, which can't be part of a URL. "
            f"If you copied it from JSON, copy only the text between the quotes: {value!r}"
        )
        return value
    if any(c.isspace() or not c.isprintable() for c in value):
        errors.append(f"{name} must not contain spaces or control characters: {value!r}")
        return value
    try:
        standard = str(_Url(url=value).url)
    except ValidationError:
        errors.append(f"{name} is not a valid http(s) URL: {value!r}")
        return value
    parts = urlsplit(value)
    if parts.username or parts.password:
        errors.append(f"{name} must not contain a user name or password")
    elif standard != value:
        errors.append(f"{name} must be written as {standard!r} (lower-case, no default port), not {value!r}")
    if parts.query or parts.fragment:
        errors.append(f"{name} must not have a query or fragment: {value!r}")
    if parts.scheme == "http" and parts.hostname not in LOCAL_HOSTS:
        errors.append(f"{name} must use https (plain http only for localhost): {value!r}")
    return value


def _same_host(url: str, other: str) -> bool:
    return urlsplit(url).hostname == urlsplit(other).hostname


def _database_url(value: str, errors: list[str]) -> None:
    """Check FLASHCARDS_DATABASE_URL without ever repeating it: it holds the password,
    so no message here includes the value or the parser's own error text."""
    name = "FLASHCARDS_DATABASE_URL"
    if not value.strip():
        errors.append(f"{name} is empty")
        return
    # A single quote may appear inside (in the user-info part), but not around the whole
    # URL, as a shell or a .env file would write it. The character itself isn't named,
    # since it could be part of the password.
    if "'" in (value[0], value[-1]) or any(
        c.isspace() or not c.isprintable() or (c in NOT_IN_URLS and c != "'") for c in value
    ):
        errors.append(
            f"{name} contains a quote, a space or another character that can't be part of a URL; "
            "copy only the URL itself (value not shown)"
        )
        return
    scheme, sep, rest = value.partition("://")
    if not sep or scheme.lower() not in ("postgresql", "postgres"):
        errors.append(f"{name} must be a postgresql:// URL (value not shown)")
        return
    # Characters such as @ / ? # in the password must be percent-encoded. Otherwise libpq
    # reads part of the password as the host or the database name, which the log shows.
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if value.count("@") != authority.count("@") or authority.count("@") > 1:
        errors.append(f"{name}: characters such as @ / ? # in the password must be percent-encoded (value not shown)")
        return
    from psycopg.conninfo import conninfo_to_dict

    try:
        params = conninfo_to_dict(value)
    except Exception:
        errors.append(f"{name} is not a valid Postgres connection URL (value not shown)")
        return
    host = str(params.get("host") or "")
    hostaddr = str(params.get("hostaddr") or "")
    port = str(params.get("port") or "5432")
    if not (port.isdigit() and 1 <= int(port) <= 65535):
        errors.append(f"{name} has an invalid port (value not shown)")
    if not host:
        errors.append(f"{name} has no host (value not shown)")
        return
    try:
        url_host = urlsplit(value).hostname or ""
    except ValueError:
        # Its message quotes the URL's user-info, password included (for example when the
        # password has U+FE6B, a small "@" that NFKC normalization turns into "@").
        errors.append(f"{name} is not a valid Postgres connection URL (value not shown)")
        return
    if url_host != host.lower():
        errors.append(f"{name}: characters such as @ / ? # in the password must be percent-encoded (value not shown)")
        return
    # hostaddr overrides where libpq actually connects, so "localhost" alone isn't proof.
    local = host in LOCAL_HOSTS and hostaddr in ("", "127.0.0.1", "::1")
    if not local and params.get("sslmode") not in ("require", "verify-ca", "verify-full"):
        errors.append(f"{name} must use sslmode=require (or verify-ca / verify-full) for a remote database")


def _database(env: Mapping[str, str], on_render: bool, errors: list[str]) -> tuple[str | None, Path | None]:
    """Which database: Postgres (FLASHCARDS_DATABASE_URL) or a SQLite file (FLASHCARDS_DB)."""
    database_url = _setting(env, "FLASHCARDS_DATABASE_URL")
    if database_url is not None:
        _database_url(database_url, errors)
        if "FLASHCARDS_DB" in env:
            errors.append("Set FLASHCARDS_DATABASE_URL or FLASHCARDS_DB, not both")
        return database_url, None
    if on_render:
        # Render's disk is wiped on every restart and deploy: a SQLite file there would
        # silently lose every card.
        errors.append("FLASHCARDS_DATABASE_URL is missing: on Render the cards must live in Postgres")
        return None, None
    db = env.get("FLASHCARDS_DB", "data/cards.db").strip()
    if not db:
        errors.append("FLASHCARDS_DB is empty")
    return None, Path(db)


def database_label(url: str) -> str:
    """Which database a URL points at, for the log: the database name and host only."""
    from psycopg.conninfo import conninfo_to_dict

    params = conninfo_to_dict(url)
    return f"{params.get('dbname') or '(default)'!r} on {params.get('host')!r}"


def _standard_origin(origin: str) -> str | None:
    """The origin as a browser would send it, or None if this isn't one. The SDK compares
    Origin headers character by character, so only this spelling can ever match. A
    trailing ':*' (any port) is kept: the SDK supports it."""
    any_port = origin.endswith(":*")
    try:
        parts = urlsplit(origin[:-2] if any_port else origin)
        port = parts.port
    except ValueError:  # a broken host such as "[::1", or a bad port
        return None
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host or "*" in host or "@" in parts.netloc:
        return None
    if parts.path or parts.query or parts.fragment:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and port != {"http": 80, "https": 443}[parts.scheme]:
        netloc += f":{port}"
    return f"{parts.scheme}://{netloc}" + (":*" if any_port else "")


def _origins(env: Mapping[str, str], errors: list[str]) -> list[str]:
    """FLASHCARDS_ALLOWED_ORIGINS: web origins such as https://claude.ai, in standard form."""
    origins = [o for o in re.split(r"[\s,]+", env.get("FLASHCARDS_ALLOWED_ORIGINS", "")) if o]
    for origin in origins:
        if any(c in NOT_IN_URLS for c in origin):
            errors.append(
                f"FLASHCARDS_ALLOWED_ORIGINS: write origins without quotes or other punctuation, like 'https://claude.ai': {origin!r}"
            )
        elif _standard_origin(origin) != origin:
            errors.append(
                "FLASHCARDS_ALLOWED_ORIGINS needs origins written like 'https://claude.ai' "
                f"(lower-case, no path, no default port): {origin!r}"
            )
    return origins


def load_settings(env: Mapping[str, str]) -> Settings:
    """Read and check every setting, reporting all problems at once."""
    errors: list[str] = []

    def url(name: str) -> tuple[str, bool]:
        """The URL setting, and whether it passed its own checks. The checks across settings
        below only run on URLs that did, so one bad value doesn't also blame a good one."""
        reported = len(errors)
        value = _url(env, name, errors)
        return value, len(errors) == reported

    issuer, issuer_ok = url("FLASHCARDS_ISSUER")
    jwks_url, jwks_ok = url("FLASHCARDS_JWKS_URL")
    resource_url, resource_ok = url("FLASHCARDS_RESOURCE_URL")

    if resource_ok:  # urlsplit raises on a broken host such as "[::1"
        path = urlsplit(resource_url).path
        if path in ("", "/") or path.endswith("/"):
            errors.append(f"FLASHCARDS_RESOURCE_URL needs a path such as /mcp, with no trailing slash: {resource_url!r}")
    # Every key published at the JWKS URL is trusted, so it must belong to the issuer.
    if issuer_ok and jwks_ok and not _same_host(jwks_url, issuer):
        errors.append(f"FLASHCARDS_JWKS_URL must be on the issuer's host ({urlsplit(issuer).hostname}): {jwks_url!r}")

    scopes = [s for s in re.split(r"[\s,]+", env.get("FLASHCARDS_SCOPES", "")) if s]
    for s in scopes:
        if s in NOT_RESOURCE_SCOPES:
            errors.append(
                f"FLASHCARDS_SCOPES must not include {s!r}: it is a sign-in scope, not this server's "
                "(Claude asks for offline_access by itself when the provider offers it)"
            )
        elif not SCOPE_TOKEN.fullmatch(s):
            errors.append(f"FLASHCARDS_SCOPES has an invalid scope name: {s!r}")

    on_render = env.get("RENDER") == "true"
    database_url, db_path = _database(env, on_render, errors)
    allowed_origins = _origins(env, errors)

    host = env.get("HOST", "").strip() or ("0.0.0.0" if on_render else "127.0.0.1")
    port_text = env.get("PORT", "8000").strip()
    port = int(port_text) if re.fullmatch(r"[0-9]{1,5}", port_text) else 0
    if not 1 <= port <= 65535:
        errors.append(f"PORT must be a number from 1 to 65535, got {port_text!r}")
    log_level = env.get("LOG_LEVEL", "INFO").strip().upper()
    if log_level not in LOG_LEVELS:
        errors.append(f"LOG_LEVEL must be one of {', '.join(LOG_LEVELS)}, got {log_level!r}")

    if errors:
        raise ConfigError("Invalid settings (see flashcards_teams/app.py):\n- " + "\n- ".join(errors))
    return Settings(
        issuer=issuer,
        jwks_url=jwks_url,
        resource_url=resource_url,
        scopes=scopes,
        db_path=db_path,
        host=host,
        port=port,
        log_level=log_level,
        on_render=on_render,
        allowed_origins=allowed_origins,
        database_url=database_url,
    )


def check_provider(settings: Settings, *, timeout: float = 5) -> None:
    """Compare the settings with the identity provider's published metadata. A
    mismatch stops the server; an unreachable provider only warns, so an outage at
    the provider can't block a restart.

    Catches the easy mistakes: a mistyped issuer (Descope then serves a different,
    project-wide document instead of an error) or a JWKS URL that isn't the provider's.
    """
    parts = urlsplit(settings.issuer)
    origin, path = f"{parts.scheme}://{parts.netloc}", parts.path.rstrip("/")
    # The order MCP clients use (RFC 8414 path insertion, then OIDC insertion and appending).
    candidates = dict.fromkeys(
        [
            f"{origin}/.well-known/oauth-authorization-server{path}",
            f"{origin}/.well-known/openid-configuration{path}",
            f"{origin}{path}/.well-known/openid-configuration",
        ]
    )
    empty_at = None
    for url in candidates:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                metadata = json.load(response)
        except (OSError, ValueError, http.client.HTTPException):  # unreachable, HTTP error or not JSON
            continue
        if not isinstance(metadata, dict) or "issuer" not in metadata:
            empty_at = empty_at or url
            continue
        problems = []
        if metadata["issuer"] != settings.issuer:
            problems.append(f"its issuer is {metadata['issuer']!r} but FLASHCARDS_ISSUER is {settings.issuer!r}")
        if metadata.get("jwks_uri") != settings.jwks_url:
            problems.append(f"its jwks_uri is {metadata.get('jwks_uri')!r} but FLASHCARDS_JWKS_URL is {settings.jwks_url!r}")
        if problems:
            raise ConfigError(f"The identity provider's metadata at {url} does not match the settings: " + "; ".join(problems))
        logger.info("The identity provider's metadata at %s matches the settings", url)
        return
    if empty_at:
        raise ConfigError(
            f"No authorization server metadata for FLASHCARDS_ISSUER={settings.issuer!r} "
            f"(empty document at {empty_at}). Copy the issuer exactly from the provider."
        )
    logger.warning("Could not reach the identity provider's metadata to double-check the settings; starting anyway")


class McpEndpointGuard:
    """In front of the MCP endpoint.

    Only POST is served. Without sessions, a 2025-era client's GET would open an event
    stream that can never carry a message and never ends; held open by the thousand,
    such streams would exhaust the instance's memory. Both protocol generations allow
    405 here, and Claude's clients treat it as "no stream offered".

    401 and 403 challenges also name the scopes this server needs (the MCP spec says
    SHOULD), so a client asks for the right scope instead of retrying.
    """

    def __init__(self, app: ASGIApp, *, path: str, scopes: list[str]) -> None:
        self.app = app
        self.path = path
        self.scope_param = f', scope="{" ".join(scopes)}"'.encode() if scopes else b""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] != self.path:
            await self.app(scope, receive, send)
            return
        if scope["method"] != "POST":
            response = PlainTextResponse("Method Not Allowed", status_code=405, headers={"Allow": "POST"})
            await response(scope, receive, send)
            return
        if not self.scope_param:
            await self.app(scope, receive, send)
            return

        async def send_with_scope(message: Message) -> None:
            if message["type"] == "http.response.start" and message["status"] in (401, 403):
                headers = [
                    (name, value + self.scope_param if name.lower() == b"www-authenticate" else value)
                    for name, value in message["headers"]
                ]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_scope)


def open_store(settings: Settings) -> CardStore:
    """Open the configured database, creating its tables if needed, and say which one."""
    if settings.database_url is not None:
        label = database_label(settings.database_url)
        logger.info("Connecting to the Postgres database %s", label)
        try:
            store = PostgresCardStore(settings.database_url)
        except StoreUnavailableError:
            raise ConfigError(
                f"Could not reach the Postgres database {label} at startup. "
                "Check FLASHCARDS_DATABASE_URL (value not shown) and that the database is running."
            ) from None
        if store.created_tables:
            logger.warning(
                "Created the card tables in the Postgres database %s, which had none. If you expected "
                "existing cards, check FLASHCARDS_DATABASE_URL.",
                label,
            )
        else:
            logger.info("Opened the existing card tables in the Postgres database %s", label)
        return store
    assert settings.db_path is not None
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    if settings.db_path.exists():
        logger.info("Opened existing database %s", settings.db_path)
    else:
        logger.warning(
            "Created a NEW empty database at %s. If you expected existing cards, check FLASHCARDS_DB "
            "and whether this disk survives restarts.",
            settings.db_path,
        )
    return SqliteCardStore(settings.db_path)


def build_app(settings: Settings, store: CardStore | None = None) -> Starlette:
    """The ASGI app. ``app.state.store`` is the open store, for closing at shutdown."""
    store = store if store is not None else open_store(settings)
    mcp = create_server(
        store=store,
        token_verifier=JwtTokenVerifier(issuer=settings.issuer, audience=settings.resource_url, jwks_url=settings.jwks_url),
        issuer_url=settings.issuer,
        resource_url=settings.resource_url,
        required_scopes=settings.scopes,
    )
    resource = urlsplit(settings.resource_url)
    app = mcp.streamable_http_app(
        streamable_http_path=resource.path,
        # No per-connection sessions: every request carries its own token and is
        # checked on its own, a restart loses nothing, and no session cap to exhaust.
        stateless_http=True,
        # Only answer requests addressed to this server's own name (DNS rebinding protection).
        # Requests without an Origin header (most clients) always pass; one that carries an
        # Origin must come from this server's own origin or one listed in the settings.
        transport_security=TransportSecuritySettings(
            allowed_hosts=[resource.netloc],
            allowed_origins=[f"{resource.scheme}://{resource.netloc}", *settings.allowed_origins],
        ),
    )
    app.state.store = store
    # /mcp/ would otherwise redirect to /mcp - behind Render's proxy, to plain http://.
    app.router.redirect_slashes = False
    # The SDK serves the protected resource metadata only at the path-specific URL;
    # Anthropic recommends the root URL as well.
    specific = f"/.well-known/oauth-protected-resource{resource.path}"
    metadata_route = next(r for r in app.router.routes if isinstance(r, Route) and r.path == specific)
    app.router.routes.append(
        Route("/.well-known/oauth-protected-resource", endpoint=metadata_route.endpoint, methods=["GET", "OPTIONS"])
    )
    app.add_middleware(McpEndpointGuard, path=resource.path, scopes=settings.scopes)
    return app


def server_options(settings: Settings) -> dict[str, Any]:
    """uvicorn settings. log_config=None keeps uvicorn's lines in the app's log format."""
    options: dict[str, Any] = {
        "host": settings.host,
        "port": settings.port,
        "workers": WORKERS,
        "timeout_keep_alive": KEEP_ALIVE_SECONDS,
        "limit_concurrency": MAX_CONNECTIONS,
        "log_config": None,
    }
    if settings.on_render:
        # Only Render's edge can reach the container, so its X-Forwarded-* headers can be
        # trusted. They are used for logs only, never for access decisions.
        options["forwarded_allow_ips"] = "*"
    return options
