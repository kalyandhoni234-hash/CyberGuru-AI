"""Contract tests for the database service (no real Postgres connection).

conftest replaces ``services.db_service`` with a route-level stub, so load the
real module from its file under a private name for these unit tests.
"""

import importlib.util
from pathlib import Path


_SPEC = importlib.util.spec_from_file_location(
    "real_db_service", Path(__file__).resolve().parent.parent / "services" / "db_service.py"
)
db = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(db)


class FakeCursor:
    def __init__(self, row=None, rows=None):
        self.row = row
        self.rows = rows or []
        self.sql = None
        self.params = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.sql = sql
        self.params = params

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.committed = False

    def cursor(self, *a, **k):
        return self._cursor

    def commit(self):
        self.committed = True


class FakeContext:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self.conn

    def __exit__(self, *exc):
        return False


def _install(monkeypatch, cursor):
    conn = FakeConnection(cursor)
    monkeypatch.setattr(db, "get_db", lambda: FakeContext(conn))
    return conn


def test_cache_query_is_user_scoped_and_excludes_invalid_results(monkeypatch):
    cursor = FakeCursor(row=None)
    _install(monkeypatch, cursor)

    db.find_recent_investigation("hash", user_id=42, max_age_hours=24)

    sql = " ".join(cursor.sql.split()).lower()
    assert "user_id = %s" in sql
    assert "analysis_error is null" in sql
    assert "analysis_valid" in sql
    assert "verdict is not null" in sql
    assert cursor.params == ("hash", 42, "24")


def test_save_investigation_persists_validation_and_type(monkeypatch):
    cursor = FakeCursor(row={"id": 9})
    conn = _install(monkeypatch, cursor)

    db.save_investigation(
        user_id=42,
        artifact_hash="hash",
        artifact_text="text",
        verdict="suspicious",
        severity="high",
        mitre={"id": "T1110", "name": "Brute Force"},
        iocs={"ips": ["8.8.8.8"]},
        threat_intel={"abuseipdb": []},
        report="report",
        analysis_error=None,
        confidence=55,
        analysis_text="narrative",
        analysis_valid=True,
        artifact_type="log",
    )

    sql = " ".join(cursor.sql.split()).lower()
    assert "analysis_text" in sql
    assert "analysis_valid" in sql
    assert "artifact_type" in sql
    assert cursor.params[-3:] == ("narrative", True, "log")
    assert conn.committed is True


def test_status_only_update_preserves_notes(monkeypatch):
    cursor = FakeCursor(row={"id": 1, "analyst_status": "Resolved", "analyst_notes": "kept"})
    _install(monkeypatch, cursor)

    db.update_investigation_analyst(1, 42, "Resolved", None)

    sql = " ".join(cursor.sql.split()).lower()
    assert "coalesce(%s, analyst_notes)" in sql
    assert cursor.params == ("Resolved", None, 1, 42)


def test_history_limit_is_clamped(monkeypatch):
    cursor = FakeCursor(rows=[])
    _install(monkeypatch, cursor)

    db.get_investigation_history(42, limit=10_000)
    assert cursor.params == (42, 100)

    db.get_investigation_history(42, limit="nonsense")
    assert cursor.params == (42, 20)


def test_owner_scoping_on_read_update_delete(monkeypatch):
    cursor = FakeCursor(row={"id": 1})
    _install(monkeypatch, cursor)

    for call in (
        lambda: db.get_investigation_by_id(1, 42),
        lambda: db.update_investigation_analyst(1, 42, "New", None),
        lambda: db.delete_investigation(1, 42),
    ):
        call()
        sql = " ".join(cursor.sql.split()).lower()
        assert "user_id = %s" in sql
        assert 42 in cursor.params
