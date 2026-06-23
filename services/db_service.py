"""
Database service — Postgres via psycopg2 with a thread-safe connection pool.

FIX #5: Previously, every request called psycopg2.connect() directly, opening
a new TCP connection each time. Under load this exhausts Neon's connection limit
(~100 connections on the free tier) and adds ~100ms of latency per request.

ThreadedConnectionPool maintains a pool of 2–10 persistent connections, reusing
them across requests. getconn() borrows a connection; putconn() returns it.
The pool is initialised once at module import (i.e. at server startup).
"""

import os
import logging
import psycopg2
import psycopg2.extras
import psycopg2.pool

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not found")

# Pool size: min 2 keeps connections warm; max 10 stays within Neon free tier.
# Adjust max based on your Render plan and Neon connection limit.
_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=2,
    maxconn=10,
    dsn=DATABASE_URL,
    cursor_factory=psycopg2.extras.RealDictCursor,
)


class _PooledConnection:
    """
    Context manager that borrows a connection from the pool and returns it.

    FIX #8: Neon (and most managed Postgres free tiers) silently closes
    connections that have been idle for a while. The pool doesn't know this
    happened until a query is actually run on that connection, which used to
    surface as an unhandled psycopg2.OperationalError ("SSL connection has
    been closed unexpectedly") on whatever request happened to draw it —
    most visibly during /auth/callback, crashing login with a 500.

    Now every checkout is "pinged" with a cheap SELECT 1 first. If that fails,
    the dead connection is discarded (not returned to the pool) and a fresh
    one is opened instead, transparently, before the caller ever sees it.
    Connections that error out *during* use are also discarded rather than
    recycled, since a connection that failed mid-query may be left in an
    inconsistent state.
    """

    def __init__(self):
        self._conn = None

    @staticmethod
    def _is_alive(conn) -> bool:
        if conn is None or conn.closed:
            return False
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            return True
        except Exception:
            return False

    def __enter__(self):
        last_conn = None
        for _ in range(2):  # one retry is enough for a stale-on-checkout connection
            candidate = _pool.getconn()
            if self._is_alive(candidate):
                self._conn = candidate
                return self._conn
            last_conn = candidate
            try:
                _pool.putconn(candidate, close=True)
            except Exception:
                logger.exception("DB pool: failed to discard dead connection")
        # Both attempts were dead — hand back whatever we last got so the
        # caller's own error handling/logging still fires with a clear cause.
        self._conn = last_conn
        return self._conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._conn:
            is_connection_error = isinstance(exc_val, (psycopg2.OperationalError, psycopg2.InterfaceError))
            if exc_type and not is_connection_error:
                # Roll back any uncommitted work on error before returning
                # the connection to the pool so it's in a clean state.
                try:
                    self._conn.rollback()
                except Exception:
                    pass
            try:
                _pool.putconn(self._conn, close=is_connection_error)
            except Exception:
                logger.exception("DB pool: failed to return connection")
        return False   # do not suppress exceptions


def get_db():
    """Return a context manager that yields a pooled Postgres connection."""
    return _PooledConnection()


def init_db():
    """Create tables and indexes if they do not already exist."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id         SERIAL PRIMARY KEY,
                    google_id  TEXT UNIQUE NOT NULL,
                    email      TEXT NOT NULL,
                    name       TEXT,
                    avatar     TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id              SERIAL PRIMARY KEY,
                    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    artifact_hash   TEXT NOT NULL,
                    artifact_text   TEXT NOT NULL,
                    verdict         TEXT,
                    severity        TEXT,
                    mitre_id        TEXT,
                    mitre_name      TEXT,
                    iocs            JSONB,
                    threat_intel    JSONB,
                    report          TEXT,
                    analysis_error  TEXT,
                    created_at      TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            # FIX #7 (schema): chat_sessions and messages tables for
            # persistent server-side conversation history.
            cur.execute("""
                CREATE TABLE IF NOT EXISTS chat_sessions (
                    id          SERIAL PRIMARY KEY,
                    user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    title       TEXT NOT NULL DEFAULT 'New conversation',
                    created_at  TIMESTAMPTZ DEFAULT NOW(),
                    updated_at  TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id          SERIAL PRIMARY KEY,
                    session_id  INTEGER REFERENCES chat_sessions(id) ON DELETE CASCADE,
                    role        TEXT NOT NULL CHECK (role IN ('user', 'bot')),
                    content     TEXT NOT NULL,
                    created_at  TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigations_hash
                ON investigations (artifact_hash)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigations_user
                ON investigations (user_id, created_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_chat_sessions_user
                ON chat_sessions (user_id, updated_at DESC)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_session
                ON messages (session_id, created_at ASC)
            """)

            # ── User Profiles (Skill Intelligence) ──
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_profiles (
                    id                   SERIAL PRIMARY KEY,
                    user_id              INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    skill_level          TEXT NOT NULL DEFAULT 'beginner'
                                         CHECK (skill_level IN ('beginner', 'intermediate', 'advanced')),
                    career_path          TEXT,
                    onboarding_completed BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at           TIMESTAMPTZ DEFAULT NOW(),
                    updated_at           TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS learning_progress (
                    id                   SERIAL PRIMARY KEY,
                    user_id              INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    completed_lessons    INTEGER NOT NULL DEFAULT 0,
                    completed_quizzes    INTEGER NOT NULL DEFAULT 0,
                    completed_labs       INTEGER NOT NULL DEFAULT 0,
                    current_topic        TEXT,
                    progress_percentage  NUMERIC(5,2) DEFAULT 0.00,
                    updated_at           TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_user_profiles_user
                ON user_profiles (user_id)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_learning_progress_user
                ON learning_progress (user_id)
            """)
        conn.commit()


# ==========================
# USER OPERATIONS
# ==========================

def upsert_user(google_id, email, name, avatar):
    """Insert or update a user row, return the row as a dict."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (google_id, email, name, avatar)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (google_id) DO UPDATE SET
                    email  = EXCLUDED.email,
                    name   = EXCLUDED.name,
                    avatar = EXCLUDED.avatar
                RETURNING *
            """, (google_id, email, name, avatar))
            conn.commit()
            return cur.fetchone()


# ==========================
# INVESTIGATION OPERATIONS
# ==========================

def save_investigation(
    user_id,
    artifact_hash,
    artifact_text,
    verdict,
    severity,
    mitre,
    iocs,
    threat_intel,
    report,
    analysis_error=None
):
    """Persist an investigation result, return the row as a dict."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO investigations (
                    user_id, artifact_hash, artifact_text, verdict, severity,
                    mitre_id, mitre_name, iocs, threat_intel, report, analysis_error
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (
                user_id,
                artifact_hash,
                artifact_text,
                verdict,
                severity,
                mitre.get("id") if mitre else None,
                mitre.get("name") if mitre else None,
                psycopg2.extras.Json(iocs or {}),
                psycopg2.extras.Json(threat_intel or {}),
                report,
                analysis_error
            ))
            conn.commit()
            return cur.fetchone()


def find_recent_investigation(artifact_hash, user_id, max_age_hours=24):
    """
    Return the most recent investigation matching this artifact hash
    AND user_id within max_age_hours, or None if not found / too old.
    Scoped per-user so two different users submitting byte-identical
    artifact text don't see each other's cached analysis.
    """
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM investigations
                WHERE artifact_hash = %s
                  AND user_id = %s
                  AND created_at > NOW() - (%s || ' hours')::INTERVAL
                ORDER BY created_at DESC
                LIMIT 1
            """, (artifact_hash, user_id, str(max_age_hours)))
            return cur.fetchone()


def get_investigation_history(user_id, limit=20):
    """Return the most recent investigations for a user."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, artifact_hash, verdict, severity, mitre_id, mitre_name,
                       iocs, created_at
                FROM investigations
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s
            """, (user_id, limit))
            return cur.fetchall()


def get_investigation_by_id(investigation_id, user_id):
    """Return a single full investigation, scoped to the requesting user."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM investigations
                WHERE id = %s AND user_id = %s
            """, (investigation_id, user_id))
            return cur.fetchone()


def delete_investigation(investigation_id, user_id):
    """Delete an investigation scoped to the user. Returns True if deleted."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM investigations
                WHERE id = %s AND user_id = %s
                RETURNING id
            """, (investigation_id, user_id))
            conn.commit()
            return cur.fetchone() is not None


# ==========================
# CHAT SESSION OPERATIONS  (FIX #7)
# ==========================

def create_chat_session(user_id, title="New conversation"):
    """Create a new chat session, return the row."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO chat_sessions (user_id, title)
                VALUES (%s, %s)
                RETURNING *
            """, (user_id, title[:120]))
            conn.commit()
            return cur.fetchone()


def get_chat_sessions(user_id, limit=50):
    """Return the user's sessions ordered by most-recently-updated."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, created_at, updated_at
                FROM chat_sessions
                WHERE user_id = %s
                ORDER BY updated_at DESC
                LIMIT %s
            """, (user_id, limit))
            return cur.fetchall()


def get_chat_session(session_id, user_id):
    """Return a single session row, scoped to the requesting user."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM chat_sessions
                WHERE id = %s AND user_id = %s
            """, (session_id, user_id))
            return cur.fetchone()


def update_chat_session_title(session_id, user_id, title):
    """Rename a session."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE chat_sessions
                SET title = %s, updated_at = NOW()
                WHERE id = %s AND user_id = %s
                RETURNING *
            """, (title[:120], session_id, user_id))
            conn.commit()
            return cur.fetchone()


def delete_chat_session(session_id, user_id):
    """Delete a session and all its messages (cascade)."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM chat_sessions
                WHERE id = %s AND user_id = %s
            """, (session_id, user_id))
            conn.commit()
            return cur.rowcount > 0


def save_message(session_id, user_id, role, content):
    """
    Append a message to a session owned by user_id and bump updated_at.
    Returns None if the session does not belong to that user.
    """
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO messages (session_id, role, content)
                SELECT id, %s, %s
                FROM chat_sessions
                WHERE id = %s AND user_id = %s
                RETURNING *
            """, (role, content, session_id, user_id))
            message = cur.fetchone()
            if not message:
                conn.rollback()
                return None
            cur.execute("""
                UPDATE chat_sessions
                SET updated_at = NOW()
                WHERE id = %s AND user_id = %s
            """, (session_id, user_id))
            conn.commit()
            return message


def get_messages(session_id, user_id, limit=200):
    """
    Return up to `limit` messages for a session, in chronological order.
    Verifies session ownership via the user_id join.
    """
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT m.id, m.role, m.content, m.created_at
                FROM messages m
                JOIN chat_sessions s ON s.id = m.session_id
                WHERE m.session_id = %s AND s.user_id = %s
                ORDER BY m.created_at ASC
                LIMIT %s
            """, (session_id, user_id, limit))
            return cur.fetchall()


# ==========================
# PROFILE OPERATIONS
# ==========================

def get_or_create_profile(user_id):
    """Return user profile, creating a default one if it doesn't exist."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM user_profiles WHERE user_id = %s", (user_id,))
            profile = cur.fetchone()
            if profile:
                return profile
            cur.execute("""
                INSERT INTO user_profiles (user_id, skill_level)
                VALUES (%s, 'beginner')
                RETURNING *
            """, (user_id,))
            conn.commit()
            return cur.fetchone()


def update_profile(user_id, skill_level=None, career_path=None, onboarding_completed=None):
    """Update profile fields. Only provided fields are updated."""
    fields = []
    values = []
    if skill_level is not None:
        fields.append("skill_level = %s")
        values.append(skill_level)
    if career_path is not None:
        fields.append("career_path = %s")
        values.append(career_path)
    if onboarding_completed is not None:
        fields.append("onboarding_completed = %s")
        values.append(onboarding_completed)
    if not fields:
        return get_or_create_profile(user_id)
    fields.append("updated_at = NOW()")
    values.append(user_id)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                UPDATE user_profiles
                SET {', '.join(fields)}
                WHERE user_id = %s
                RETURNING *
            """, values)
            conn.commit()
            row = cur.fetchone()
            if row:
                return row
            return get_or_create_profile(user_id)


def get_or_create_learning_progress(user_id):
    """Return learning progress, creating default if it doesn't exist."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM learning_progress WHERE user_id = %s", (user_id,))
            progress = cur.fetchone()
            if progress:
                return progress
            cur.execute("""
                INSERT INTO learning_progress (user_id)
                VALUES (%s)
                RETURNING *
            """, (user_id,))
            conn.commit()
            return cur.fetchone()


def update_learning_progress(user_id, **kwargs):
    """Update learning progress fields. Keys: completed_lessons, completed_quizzes,
    completed_labs, current_topic, progress_percentage."""
    fields = []
    values = []
    for key in ('completed_lessons', 'completed_quizzes', 'completed_labs', 'current_topic', 'progress_percentage'):
        if key in kwargs and kwargs[key] is not None:
            fields.append(f"{key} = %s")
            values.append(kwargs[key])
    if not fields:
        return get_or_create_learning_progress(user_id)
    fields.append("updated_at = NOW()")
    values.append(user_id)
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(f"""
                UPDATE learning_progress
                SET {', '.join(fields)}
                WHERE user_id = %s
                RETURNING *
            """, values)
            conn.commit()
            row = cur.fetchone()
            if row:
                return row
            return get_or_create_learning_progress(user_id)