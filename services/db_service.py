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
