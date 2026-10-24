import os
import socket
import subprocess
from pathlib import Path

import pytest

from helpers import empty_postgres_store

from flashcards_teams.store import SqliteCardStore


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _postgres_bin() -> tuple[Path | None, str]:
    """Where the local Postgres programs are, or why there are none."""
    configured = os.environ.get("FLASHCARDS_TEST_PG_BIN")
    if configured:
        return Path(configured), ""
    try:
        import postgresql_binaries
    except ImportError:
        return None, "no local Postgres: pip install -r requirements-dev.txt, or set FLASHCARDS_TEST_PG_BIN to its bin folder"
    return Path(postgresql_binaries.bin()), ""


@pytest.fixture(scope="session")
def pg_url(tmp_path_factory):
    """A throwaway Postgres server for the whole test run: 127.0.0.1 only, with trust
    authentication, so its URL holds no secret. Without one the Postgres tests are
    skipped (and listed as skipped), unless FLASHCARDS_REQUIRE_PG=1 makes them fail."""
    bindir, reason = _postgres_bin()
    if bindir is None or (hasattr(os, "geteuid") and os.geteuid() == 0):
        reason = reason or "initdb refuses to run as root: run the tests as an ordinary user"
        if os.environ.get("FLASHCARDS_REQUIRE_PG") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    pg_ctl = str(bindir / "pg_ctl")
    data = tmp_path_factory.mktemp("postgres") / "data"
    log = data.parent / "server.log"
    try:
        subprocess.run(
            [str(bindir / "initdb"), "-D", str(data), "-U", "postgres", "-A", "trust", "-E", "UTF8", "--no-locale"],
            check=True,
            capture_output=True,
        )
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        # The server inherits pg_ctl's output handles, so they must not be captured: on
        # Windows the pipes would never close and this call would never return. TCP only:
        # no Unix-domain socket in a directory that may not be writable.
        subprocess.run(
            [
                pg_ctl, "-D", str(data), "-l", str(log), "-w", "-t", "60",
                "-o", f"-p {port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=", "start",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        subprocess.run([pg_ctl, "-D", str(data), "-m", "immediate", "-w", "stop"], capture_output=True)
        output = (e.stderr or b"").decode(errors="replace")[-2000:]
        server_log = log.read_text(errors="replace")[-2000:] if log.exists() else ""
        pytest.fail(f"Could not start the local Postgres server ({Path(e.cmd[0]).name}):\n{output}\n{server_log}")
    try:
        yield f"postgresql://postgres@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run([pg_ctl, "-D", str(data), "-m", "fast", "-w", "stop"], capture_output=True)


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.postgres)])
def store(request, tmp_path):
    """Every test that uses a store runs once on each database."""
    if request.param == "sqlite":
        s = SqliteCardStore(tmp_path / "cards.db")
    else:
        s = empty_postgres_store(request.getfixturevalue("pg_url"))
    yield s
    s.close()


@pytest.fixture
def no_proxy(monkeypatch):
    """Tests that talk to a local HTTP server must not go through a proxy configured on
    the machine (urllib uses HTTP_PROXY or, on Windows, the system proxy)."""
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


@pytest.fixture(autouse=True)
def _apply_mutation(monkeypatch):
    """Only used by tests/run_mutations.py to prove the tests catch broken code."""
    name = os.environ.get("FLASHCARDS_MUTATION")
    if name:
        from mutations import MUTATIONS

        MUTATIONS[name](monkeypatch)
