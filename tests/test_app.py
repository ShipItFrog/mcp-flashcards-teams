"""The deployable app (flashcards_teams/app.py): bad settings stop it before it
starts; the assembled app serves the right metadata, accepts a real signed token
and refuses what it must; the startup check against the identity provider; and
the server limits."""

import logging
import urllib.error
import urllib.request
from contextlib import asynccontextmanager

import anyio
import httpx2
import jwt
import pytest
import uvicorn
from helpers import HEADERS, INITIALIZE
from jwt_helpers import DROP, JWKS, JsonServer, sign

from flashcards_teams.app import ConfigError, build_app, check_provider, load_settings, server_options

pytestmark = pytest.mark.anyio

# A path-style issuer, like the ones identity providers use for MCP servers. It
# must come back exactly as configured: clients compare issuers character by character.
ISSUER = "https://auth.example.test/v1/apps/P123/M456"
JWKS_URL = "https://auth.example.test/P123/.well-known/jwks.json"
ORIGIN = "https://flashcards.example.test"
RESOURCE = f"{ORIGIN}/mcp"
METADATA = f"{ORIGIN}/.well-known/oauth-protected-resource/mcp"
MODERN = {"MCP-Protocol-Version": "2026-07-28"}
META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "raw-test", "version": "0"},
}


def env(tmp_path, **overrides):
    values = {
        "FLASHCARDS_ISSUER": ISSUER,
        "FLASHCARDS_JWKS_URL": JWKS_URL,
        "FLASHCARDS_RESOURCE_URL": RESOURCE,
        "FLASHCARDS_SCOPES": "flashcards",
        "FLASHCARDS_DB": str(tmp_path / "cards.db"),
    }
    values.update(overrides)
    return {k: v for k, v in values.items() if v is not None}


def make_app(tmp_path, **overrides):
    return build_app(load_settings(env(tmp_path, **overrides)))


def client(app, host="flashcards.example.test", token=None, headers=None):
    headers = {**(headers or {}), **({"Authorization": f"Bearer {token}"} if token else {})}
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url=f"https://{host}", headers=headers)


def token(**overrides):
    return sign(iss=ISSUER, aud=RESOURCE, **overrides)


@pytest.fixture
def keys(monkeypatch):
    """Serve the test keys instead of fetching them, and record which URL was asked for."""
    asked = []

    def fetch(self):
        asked.append(self.uri)
        return JWKS

    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", fetch)
    return asked


@asynccontextmanager
async def running(app):
    # ASGITransport doesn't run the app's lifespan, so start it here.
    async with app.router.lifespan_context(app):
        yield


# --- what the assembled app serves ---


async def test_metadata_names_this_server_and_the_issuer_exactly(tmp_path):
    async with client(make_app(tmp_path)) as hc:
        specific = await hc.get("/.well-known/oauth-protected-resource/mcp")
        root = await hc.get("/.well-known/oauth-protected-resource")
    assert specific.status_code == 200
    body = specific.json()
    assert body["resource"] == RESOURCE
    assert body["authorization_servers"] == [ISSUER]
    assert body["scopes_supported"] == ["flashcards"]
    # Also at the root, as Anthropic recommends; same document.
    assert root.status_code == 200 and root.json() == body


async def test_without_scopes_the_metadata_lists_none(tmp_path):
    # Leaving scopes_supported out (rather than []) lets clients request no scope.
    async with client(make_app(tmp_path, FLASHCARDS_SCOPES=None)) as hc:
        body = (await hc.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert "scopes_supported" not in body


async def test_no_token_gets_401_pointing_at_the_metadata_and_naming_the_scope(tmp_path):
    async with client(make_app(tmp_path)) as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
    assert r.status_code == 401
    challenge = r.headers["www-authenticate"]
    assert f'resource_metadata="{METADATA}"' in challenge
    assert challenge.endswith(', scope="flashcards"')


async def test_token_without_the_scope_gets_403_naming_the_scope(tmp_path, keys):
    app = make_app(tmp_path)
    async with running(app), client(app, token=token(scope=DROP)) as hc:
        r = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
    assert r.status_code == 403
    assert 'error="insufficient_scope"' in r.headers["www-authenticate"]
    assert r.headers["www-authenticate"].endswith(', scope="flashcards"')


async def test_signed_token_works_only_for_this_host_and_origin(tmp_path, keys):
    app = make_app(tmp_path)
    async with running(app):
        async with client(app, token=token()) as hc:
            ok = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
            same_origin = await hc.post("/mcp", json=INITIALIZE, headers={**HEADERS, "Origin": ORIGIN})
            other_origin = await hc.post("/mcp", json=INITIALIZE, headers={**HEADERS, "Origin": "https://evil.example.test"})
        async with client(app, host="attacker.example.test", token=token()) as hc:
            wrong_host = await hc.post("/mcp", json=INITIALIZE, headers=HEADERS)
    assert ok.status_code == 200
    # Stateless: no session is created, so there is no session cap to exhaust.
    assert "mcp-session-id" not in ok.headers
    assert keys and set(keys) == {JWKS_URL}  # the configured key URL is the one used
    assert same_origin.status_code == 200
    assert other_origin.status_code == 403
    assert wrong_host.status_code == 421


@pytest.mark.parametrize("method", ["GET", "DELETE", "PUT", "HEAD"])
@pytest.mark.parametrize("protocol", [{}, MODERN], ids=["legacy", "modern"])
async def test_only_post_is_served(tmp_path, keys, method, protocol):
    # A 2025-era GET would otherwise open an event stream that never ends.
    app = make_app(tmp_path)
    async with running(app), client(app, token=token()) as hc:
        with anyio.fail_after(5):
            r = await hc.request(method, "/mcp", headers={**HEADERS, **protocol})
    assert r.status_code == 405
    assert r.headers["allow"] == "POST"


async def test_subscriptions_are_not_offered(tmp_path, keys):
    # Nothing here changes on its own; a subscriptions/listen stream would only be held open.
    app = make_app(tmp_path)

    def modern(method):
        return {**HEADERS, **MODERN, "Mcp-Method": method}

    async with running(app), client(app, token=token()) as hc:
        with anyio.fail_after(5):
            discover = await hc.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": META}},
                headers=modern("server/discover"),
            )
            listen = await hc.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "subscriptions/listen",
                    "params": {"notifications": {"toolsListChanged": True}, "_meta": META},
                },
                headers=modern("subscriptions/listen"),
            )
    capabilities = discover.json()["result"]["capabilities"]
    assert capabilities["tools"].get("listChanged") is False
    assert listen.json()["error"]["code"] == -32601  # method not found


@pytest.mark.parametrize(
    ("allowed", "origin", "status"),
    [
        ("", "https://claude.ai", 403),
        ("https://claude.ai", "https://claude.ai", 200),
        ("https://claude.ai https://claude.com", "https://claude.com", 200),
        ("https://claude.ai", "https://evil.example.test", 403),
    ],
    ids=["not-listed", "listed", "second-listed", "other-origin"],
)
async def test_signed_requests_from_listed_origins_are_served(tmp_path, keys, allowed, origin, status):
    # The Origin check runs after sign-in: an unsigned request gets 401 whatever its
    # Origin, so this is what a signed-in client sending an Origin header meets.
    app = make_app(tmp_path, FLASHCARDS_ALLOWED_ORIGINS=allowed or None)
    async with running(app), client(app, token=token()) as hc:
        response = await hc.post("/mcp", json=INITIALIZE, headers={**HEADERS, "Origin": origin})
    assert response.status_code == status


async def test_a_trailing_slash_is_not_redirected(tmp_path):
    # Behind Render's proxy the redirect would point at plain http://.
    async with client(make_app(tmp_path)) as hc:
        r = await hc.post("/mcp/", json=INITIALIZE, headers=HEADERS)
    assert r.status_code == 404


async def test_a_new_database_is_announced_and_an_existing_one_reused(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="flashcards_teams.app"):
        make_app(tmp_path)
        make_app(tmp_path)
    first, second = [r for r in caplog.records if "database" in r.getMessage()]
    assert first.levelno == logging.WARNING and "NEW empty database" in first.getMessage()
    assert second.levelno == logging.INFO and "existing database" in second.getMessage()


# --- settings ---


BAD_SETTINGS = {
    "missing-issuer": {"FLASHCARDS_ISSUER": None},
    "missing-key-url": {"FLASHCARDS_JWKS_URL": None},
    "missing-resource": {"FLASHCARDS_RESOURCE_URL": None},
    "plain-http-issuer": {"FLASHCARDS_ISSUER": "http://auth.example.test/v1/apps/P123/M456"},
    "plain-http-resource": {"FLASHCARDS_RESOURCE_URL": "http://flashcards.example.test/mcp"},
    "not-a-url": {"FLASHCARDS_ISSUER": "auth.example.test"},
    "resource-without-path": {"FLASHCARDS_RESOURCE_URL": ORIGIN},
    "resource-with-trailing-slash": {"FLASHCARDS_RESOURCE_URL": RESOURCE + "/"},
    "resource-with-query": {"FLASHCARDS_RESOURCE_URL": RESOURCE + "?x=1"},
    # Spellings the metadata would quietly normalize while token and Host checks compare exactly.
    "upper-case-host": {"FLASHCARDS_RESOURCE_URL": "https://Flashcards.example.test/mcp"},
    "upper-case-scheme": {"FLASHCARDS_RESOURCE_URL": "HTTPS://flashcards.example.test/mcp"},
    "default-port-written-out": {"FLASHCARDS_RESOURCE_URL": "https://flashcards.example.test:443/mcp"},
    "user-name-in-url": {"FLASHCARDS_RESOURCE_URL": "https://me@flashcards.example.test/mcp"},
    "non-ascii-host": {"FLASHCARDS_RESOURCE_URL": "https://flashcárds.example.test/mcp"},
    "tab-in-url": {"FLASHCARDS_RESOURCE_URL": "https://flashcards.example.test/m\tcp"},
    "space-in-url": {"FLASHCARDS_ISSUER": "https://auth.example.test/v1/apps/P123 /M456"},
    # urlsplit raises on these: a settings message, not a crash.
    "broken-ipv6-host": {"FLASHCARDS_RESOURCE_URL": "https://[::1/mcp"},
    "stray-bracket-in-host": {"FLASHCARDS_RESOURCE_URL": "https://flashcards.example.test]/mcp"},
    "upper-case-issuer-host": {"FLASHCARDS_ISSUER": "https://AUTH.example.test/v1/apps/P123/M456"},
    "issuer-with-query": {"FLASHCARDS_ISSUER": ISSUER + "?x=1"},
    "key-url-on-another-host": {"FLASHCARDS_JWKS_URL": "https://auth.example.co/P123/.well-known/jwks.json"},
    "offline-access-in-scopes": {"FLASHCARDS_SCOPES": "flashcards offline_access"},
    "openid-in-scopes": {"FLASHCARDS_SCOPES": "openid"},
    "quote-in-scope": {"FLASHCARDS_SCOPES": 'flash"cards'},
    "port-not-a-number": {"PORT": "abc"},
    "port-out-of-range": {"PORT": "70000"},
    "port-zero": {"PORT": "0"},
    "unknown-log-level": {"LOG_LEVEL": "LOUD"},
    # Render's disk is wiped on every restart: without Postgres every card would vanish.
    "render-without-a-database": {"RENDER": "true"},
    "postgres-and-sqlite-both-set": {"FLASHCARDS_DATABASE_URL": "postgresql://u:p@db.example.test/cards?sslmode=require"},
    "empty-database-url": {"FLASHCARDS_DB": None, "FLASHCARDS_DATABASE_URL": "  "},
    "origin-with-a-path": {"FLASHCARDS_ALLOWED_ORIGINS": "https://claude.ai/"},
    "origin-upper-case": {"FLASHCARDS_ALLOWED_ORIGINS": "https://Claude.ai"},
    "origin-without-scheme": {"FLASHCARDS_ALLOWED_ORIGINS": "claude.ai"},
}

REMOTE_DATABASE = {"FLASHCARDS_DB": None, "FLASHCARDS_DATABASE_URL": "postgresql://u:p@db.example.test/cards?sslmode=require"}


@pytest.mark.parametrize("overrides", BAD_SETTINGS.values(), ids=BAD_SETTINGS.keys())
def test_bad_settings_stop_the_server_before_it_starts(tmp_path, overrides):
    with pytest.raises(ConfigError):
        load_settings(env(tmp_path, **overrides))


def test_all_problems_are_reported_at_once(tmp_path):
    with pytest.raises(ConfigError) as stopped:
        load_settings(env(tmp_path, FLASHCARDS_ISSUER=None, PORT="abc"))
    message = str(stopped.value)
    assert "FLASHCARDS_ISSUER is missing" in message and "PORT must be" in message


@pytest.mark.parametrize(
    ("name", "attribute", "value"),
    [
        ("FLASHCARDS_ISSUER", "issuer", ISSUER),
        ("FLASHCARDS_JWKS_URL", "jwks_url", JWKS_URL),
        ("FLASHCARDS_RESOURCE_URL", "resource_url", RESOURCE),
    ],
    ids=["issuer", "key-url", "resource"],
)
def test_spaces_and_line_breaks_around_a_url_are_ignored(tmp_path, name, attribute, value):
    # Copy buttons and Render's multi-line value box add them. What is kept must be the
    # clean value: the token and Host checks compare it exactly.
    settings = load_settings(env(tmp_path, **{name: f"  {value}\r\n"}))
    assert getattr(settings, attribute) == value


@pytest.mark.parametrize(
    ("name", "value"),
    [
        # Copied from the provider's raw metadata together with the next field.
        ("FLASHCARDS_ISSUER", ISSUER + '","jwks_uri":"https://auth.example.test/P123/.well-'),
        ("FLASHCARDS_JWKS_URL", '"authorization_endpoint":"https://auth.example.test/oauth2/authorize'),
        ("FLASHCARDS_ISSUER", f'"{ISSUER}"'),
        # The same from a browser's formatted view, which adds spaces.
        ("FLASHCARDS_ISSUER", ISSUER + '", "jwks_uri": "https://auth.example.test/P123/.well-known/jwks.json'),
    ],
    ids=["issuer", "key-url", "quoted-issuer", "formatted-json"],
)
def test_a_url_copied_with_its_json_says_to_copy_only_the_text(tmp_path, name, value):
    with pytest.raises(ConfigError) as stopped:
        load_settings(env(tmp_path, **{name: value}))
    message = str(stopped.value)
    assert "copy only the text between the quotes" in message
    # Not the percent-encoded spelling of the pasted fragment as a suggestion.
    assert "%22" not in message and "must be written as" not in message
    # One problem, one message: the other URL settings, which are fine, aren't blamed too.
    assert message.count("\n- ") == 1


@pytest.mark.parametrize("char", list("\"'<>\\^`{|}"))
def test_characters_that_never_belong_in_a_url_are_explained(tmp_path, char):
    with pytest.raises(ConfigError) as stopped:
        load_settings(env(tmp_path, FLASHCARDS_ISSUER=ISSUER + char))
    message = str(stopped.value)
    assert f"contains {char!r}" in message and "copy only the text between the quotes" in message
    assert "must be written as" not in message


def test_plain_http_is_allowed_on_this_machine(tmp_path):
    settings = load_settings(env(tmp_path, FLASHCARDS_RESOURCE_URL="http://localhost:8000/mcp"))
    assert settings.resource_url == "http://localhost:8000/mcp"


def test_scopes_may_be_separated_by_spaces_or_commas(tmp_path):
    assert load_settings(env(tmp_path, FLASHCARDS_SCOPES="flashcards, extra other")).scopes == ["flashcards", "extra", "other"]


async def test_an_issuer_ending_in_a_slash_is_kept_exactly(tmp_path):
    # Some providers' issuers end in "/" (Auth0's do); it must not be dropped or added.
    issuer = "https://auth.example.test/"
    async with client(make_app(tmp_path, FLASHCARDS_ISSUER=issuer)) as hc:
        body = (await hc.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert body["authorization_servers"] == [issuer]


# --- server limits ---


def test_server_limits(tmp_path):
    options = server_options(load_settings(env(tmp_path)))
    # Render's edge reuses connections for up to 75 s; closing sooner causes 502s.
    assert options["timeout_keep_alive"] > 75
    # A cap on simultaneous connections turns "out of memory" into "503 for some".
    assert options["limit_concurrency"]
    assert options["workers"] == 1
    assert options["host"] == "127.0.0.1"
    assert "forwarded_allow_ips" not in options


def test_on_render_listen_on_all_interfaces_and_trust_its_proxy(tmp_path):
    options = server_options(load_settings(env(tmp_path, RENDER="true", PORT="10000", **REMOTE_DATABASE)))
    assert options["host"] == "0.0.0.0" and options["port"] == 10000
    assert options["forwarded_allow_ips"] == "*"


def test_one_process_whatever_web_concurrency_says(tmp_path, monkeypatch):
    # Render sets WEB_CONCURRENCY; uvicorn reads it unless workers is given, and exits at
    # startup when it is above 1 and the app is passed as an object. uvicorn's own Config
    # decides, so ask it.
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    options = server_options(load_settings(env(tmp_path, RENDER="true", **REMOTE_DATABASE)))
    assert uvicorn.Config(make_app(tmp_path), **options).workers == 1


# --- the database setting ---


SENTINEL = "pw-SENTINEL-4711"


def test_a_remote_postgres_database_is_accepted_and_its_url_never_shown(tmp_path):
    url = f"postgresql://cards:{SENTINEL}@db.example.test/cards?sslmode=require"
    settings = load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=url))
    assert settings.database_url == url and settings.db_path is None
    assert SENTINEL not in repr(settings)


def test_a_line_break_after_the_database_url_is_ignored(tmp_path):
    # Otherwise it would end up inside the last query parameter and fail only at connect time.
    url = f"postgresql://neondb_owner:{SENTINEL}@ep-example-pooler.db.example.test/neondb?sslmode=require&channel_binding=require"
    settings = load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=url + "\n"))
    assert settings.database_url == url
    assert SENTINEL not in repr(settings)


QUOTED_DATABASE_URL = f'"postgresql://cards:{SENTINEL}@db.example.test/cards?sslmode=require"'


@pytest.mark.parametrize(
    "url",
    [
        f"postgresql://cards:{SENTINEL}@db.example.test/cards",  # remote without TLS
        f"mysql://cards:{SENTINEL}@db.example.test/cards",
        f"postgresql://cards:{SENTINEL}@/cards?sslmode=require",  # no host
        f"postgresql://cards:{SENTINEL}@db.example.test:notaport/cards?sslmode=require",
        # "localhost", but hostaddr sends libpq to a remote address
        f"postgresql://cards:{SENTINEL}@localhost/cards?hostaddr=203.0.113.5",
        # Unencoded @ / # in the password: libpq would read part of it as the host or the
        # database name, and the log shows both.
        f"postgresql://cards:{SENTINEL}@x@db.example.test/cards?sslmode=require",
        f"postgresql://cards:12/{SENTINEL}@db.example.test/cards?sslmode=require",
        f"postgresql://cards:{SENTINEL}#x@db.example.test/cards?sslmode=require",
        f"postgresql://cards:{SENTINEL} 2@db.example.test/cards?sslmode=require",
        QUOTED_DATABASE_URL,
        # urlsplit raises on these, and for the first its message quotes the password.
        f"postgresql://cards:{SENTINEL}﹫x@db.example.test/cards?sslmode=require",
        f"postgresql://cards:{SENTINEL}@[1.2.3.4]/cards?sslmode=require",
    ],
    ids=[
        "no-tls", "not-postgres", "no-host", "bad-port", "remote-hostaddr", "at-sign", "slash", "hash",
        "space-inside", "quoted", "nfkc-at-sign", "bracketed-ipv4",
    ],
)
def test_a_bad_database_url_is_refused_without_showing_it(tmp_path, url):
    with pytest.raises(ConfigError) as stopped:
        load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=url))
    assert "FLASHCARDS_DATABASE_URL" in str(stopped.value)
    assert SENTINEL not in str(stopped.value)


@pytest.mark.parametrize(
    "url",
    [
        QUOTED_DATABASE_URL,
        f"postgresql://cards:{SENTINEL} 2@db.example.test/cards?sslmode=require",
        f"postgresql://cards:{SENTINEL}@db.example.test/ca\trds?sslmode=require",
        # As a shell or a .env file writes it.
        f"'postgresql://cards:{SENTINEL}@db.example.test/cards?sslmode=require'",
    ],
    ids=["quoted", "space-inside", "tab-inside", "single-quoted"],
)
def test_a_database_url_with_quotes_or_spaces_says_to_copy_only_the_url(tmp_path, url):
    with pytest.raises(ConfigError) as stopped:
        load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=url))
    assert "copy only the URL itself" in str(stopped.value)
    assert SENTINEL not in str(stopped.value)


def test_a_database_url_of_only_spaces_is_reported_as_empty(tmp_path):
    with pytest.raises(ConfigError, match="FLASHCARDS_DATABASE_URL is empty"):
        load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=" \r\n "))


def test_a_database_on_this_machine_needs_no_tls(tmp_path):
    url = "postgresql://postgres@127.0.0.1:5432/postgres"
    assert load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=url)).database_url == url


def test_a_percent_encoded_password_is_fine(tmp_path):
    url = "postgresql://cards:p%40ss%2Fw%23rd@db.example.test/cards?sslmode=require&channel_binding=require"
    assert load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=url)).database_url == url


def test_a_single_quote_in_the_database_password_is_fine(tmp_path):
    # A single quote is legal in the user-info part of a URL.
    url = f"postgresql://cards:it's-{SENTINEL}@db.example.test/cards?sslmode=require"
    settings = load_settings(env(tmp_path, FLASHCARDS_DB=None, FLASHCARDS_DATABASE_URL=url))
    assert settings.database_url == url
    assert SENTINEL not in repr(settings)


@pytest.mark.parametrize(
    "origin",
    [
        "https://claude.ai:443", "https://claude.ai:abc", "https://@claude.ai", "https://*.example.test", "https://claude.ai/",
        # urlsplit raises on these: a settings message, not a crash.
        "https://[::1", "https://a℀b",
    ],
    ids=["default-port", "bad-port", "empty-user", "wildcard-host", "path", "broken-ipv6", "nfkc-host"],
)
def test_an_origin_that_could_never_match_is_refused(tmp_path, origin):
    # The SDK compares Origin headers exactly, so these would silently never match.
    with pytest.raises(ConfigError, match="FLASHCARDS_ALLOWED_ORIGINS"):
        load_settings(env(tmp_path, FLASHCARDS_ALLOWED_ORIGINS=origin))


@pytest.mark.parametrize("origin", ['"https://claude.ai"', "'https://claude.ai'"], ids=["double-quotes", "single-quotes"])
def test_a_quoted_origin_is_refused_with_a_clear_message(tmp_path, origin):
    with pytest.raises(ConfigError, match="without quotes"):
        load_settings(env(tmp_path, FLASHCARDS_ALLOWED_ORIGINS=origin))


def test_an_any_port_origin_is_kept(tmp_path):
    # The SDK supports "scheme://host:*" for any port.
    allowed = "http://localhost:* https://claude.ai"
    assert load_settings(env(tmp_path, FLASHCARDS_ALLOWED_ORIGINS=allowed)).allowed_origins == ["http://localhost:*", "https://claude.ai"]


# --- startup check against the identity provider's metadata ---


def provider(server, *, issuer=None, jwks_uri=None, document=None):
    """Settings pointing at the local server, and the metadata it publishes."""
    issuer_url = f"{server.base}/v1/apps/P1/M1"
    settings = load_settings(
        {
            "FLASHCARDS_ISSUER": issuer_url,
            "FLASHCARDS_JWKS_URL": f"{server.base}/P1/.well-known/jwks.json",
            "FLASHCARDS_RESOURCE_URL": "http://localhost:8000/mcp",
        }
    )
    metadata = document if document is not None else {
        "issuer": issuer or issuer_url,
        "jwks_uri": jwks_uri or settings.jwks_url,
    }
    server.documents["/.well-known/oauth-authorization-server/v1/apps/P1/M1"] = metadata
    return settings


def test_provider_metadata_that_matches_lets_the_server_start(no_proxy, caplog):
    with JsonServer({}) as server, caplog.at_level(logging.INFO, logger="flashcards_teams.app"):
        check_provider(provider(server))
    assert "matches the settings" in caplog.text
    # Looked where MCP clients look first, and with a User-Agent the provider accepts.
    assert server.paths[0] == "/.well-known/oauth-authorization-server/v1/apps/P1/M1"
    assert not server.agents[0].startswith("Python-urllib")


@pytest.mark.parametrize(
    "published",
    [
        # Descope answers a mistyped MCP server ID with the project-wide document.
        lambda base: {"issuer": f"{base}/v1/apps/P1"},
        lambda base: {"jwks_uri": "https://keys.example.test/other.json"},
    ],
    ids=["other-issuer", "other-key-url"],
)
def test_provider_metadata_that_disagrees_stops_the_server(no_proxy, published):
    with JsonServer({}) as server:
        settings = provider(server, **published(server.base))
        with pytest.raises(ConfigError, match="does not match"):
            check_provider(settings)


def test_an_empty_provider_document_stops_the_server(no_proxy):
    # Descope answers unknown project or server IDs with 200 and {}.
    with JsonServer({}) as server:
        settings = provider(server, document={})
        with pytest.raises(ConfigError, match="No authorization server metadata"):
            check_provider(settings)


def test_an_unreachable_provider_only_warns(no_proxy, monkeypatch, caplog):
    # An outage at the provider must not stop a restart.
    def unreachable(*args, **kwargs):
        raise urllib.error.URLError("connection refused")

    with JsonServer({}) as server:
        settings = provider(server)
    monkeypatch.setattr(urllib.request, "urlopen", unreachable)
    with caplog.at_level(logging.WARNING, logger="flashcards_teams.app"):
        check_provider(settings)
    assert "Could not reach the identity provider" in caplog.text
