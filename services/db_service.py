import os
import psycopg2
import psycopg2.extras

DATABASE_URL = os.getenv("DATABASE_URL")  # Neon connection string
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable not found")


def get_db():
    """Open a new Postgres connection. Use as a context manager."""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn


def init_db():
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
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigations_hash
                ON investigations (artifact_hash)
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigations_user
                ON investigations (user_id, created_at DESC)
            """)
        conn.commit()


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


def find_recent_investigation(artifact_hash, max_age_hours=24):
    """
    Return the most recent investigation matching this artifact hash
    within max_age_hours, or None if not found / too old.
    """
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM investigations
                WHERE artifact_hash = %s
                  AND created_at > NOW() - INTERVAL '%s hours'
                ORDER BY created_at DESC
                LIMIT 1
            """, (artifact_hash, max_age_hours))
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
