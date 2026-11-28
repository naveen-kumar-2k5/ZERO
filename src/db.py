"""Database connection helper."""
import psycopg2
import psycopg2.extras

from .config import DB_CONFIG


def get_conn():
    """psycopg2 connection. Returns dicts from cursors via RealDictCursor."""
    return psycopg2.connect(cursor_factory=psycopg2.extras.RealDictCursor, **DB_CONFIG)