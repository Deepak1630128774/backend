import sqlite3
from contextlib import contextmanager
from typing import Iterator

from .settings import DB_PATH, FUEL_DB_PATH, PROJECT_DB_PATH, STRATEGY_DB_PATH

DB_MAP = {
    "npv": DB_PATH,
    "fuel": FUEL_DB_PATH,
    "co2": PROJECT_DB_PATH,
    "strategy": STRATEGY_DB_PATH,
}


@contextmanager
def get_connection(db_key: str) -> Iterator[sqlite3.Connection]:
    if db_key not in DB_MAP:
        raise ValueError(f"Unknown db key: {db_key}")
    conn = sqlite3.connect(str(DB_MAP[db_key]))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def row_to_dict(row: sqlite3.Row) -> dict:
    return {k: row[k] for k in row.keys()}


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict]:
    return [row_to_dict(row) for row in rows]

