import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from database import DATABASE_URL, DB_PATH, get_db, init_db, psycopg


TABLE_COLUMNS = {
    "users": ("id", "name", "email", "password_hash", "created_at", "session_version"),
    "scans": ("id", "user_id", "url", "result", "risk_score", "created_at", "signals_json"),
    "password_reset_tokens": ("user_id", "token_hash", "expires_at"),
    "user_settings": ("user_id", "preferences_json"),
}
TABLE_DEFAULTS = {
    "users": {"created_at": None, "session_version": 0},
    "scans": {"signals_json": "[]"},
}
IDENTITY_TABLES = ("users", "scans")
REQUIRED_SOURCE_TABLES = ("users", "scans")


def create_backup(source_path):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = source_path.with_name(
        f"{source_path.stem}.pre-postgres-{timestamp}{source_path.suffix}"
    )
    if backup_path.exists():
        raise FileExistsError(f"Refusing to overwrite backup file: {backup_path}")

    source = sqlite3.connect(source_path)
    backup = sqlite3.connect(backup_path)
    try:
        source.backup(backup)
    finally:
        backup.close()
        source.close()
    return backup_path


def normalize_timestamp(value):
    if value is None or isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def source_rows(source, table):
    table_exists = source.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if not table_exists:
        return None
    cursor = source.execute(f'SELECT * FROM "{table}"')
    return cursor


def ensure_destination_empty():
    if psycopg is None:
        raise RuntimeError("Install the psycopg dependency to use DATABASE_URL.")
    with psycopg.connect(DATABASE_URL, connect_timeout=10) as destination:
        for table in TABLE_COLUMNS:
            exists = destination.execute(
                "SELECT to_regclass(%s) IS NOT NULL AS exists",
                (table,),
            ).fetchone()[0]
            if exists:
                count = destination.execute(
                    f'SELECT COUNT(*) AS count FROM "{table}"'
                ).fetchone()[0]
                if count:
                    raise RuntimeError(
                        f"Destination table {table!r} is not empty; no rows were migrated."
                    )


def row_values(table, row):
    available = set(row.keys())
    values = {}
    for column in TABLE_COLUMNS[table]:
        if column in available:
            value = row[column]
        else:
            value = TABLE_DEFAULTS.get(table, {}).get(column)
            if value is None and column not in TABLE_DEFAULTS.get(table, {}):
                raise ValueError(f"SQLite table {table!r} is missing required column {column!r}.")
        if column == "created_at":
            value = normalize_timestamp(value)
        if table == "scans" and column == "result" and value in (
            "likely_legitimate",
            "suspicious",
            "phishing",
        ):
            risk = row["risk_score"]
            value = "malicious" if risk >= 60 else "phishing" if risk >= 30 else "safe"
        values[column] = value
    return values


def migrate(source_path):
    if not DATABASE_URL:
        raise RuntimeError("Set DATABASE_URL to the Supabase PostgreSQL connection string.")
    if not source_path.is_file():
        raise FileNotFoundError(f"SQLite database not found: {source_path}")

    backup_path = create_backup(source_path)
    source = sqlite3.connect(backup_path)
    source.row_factory = sqlite3.Row
    source.execute("PRAGMA query_only = ON")
    try:
        source_counts = {}
        for table in TABLE_COLUMNS:
            cursor = source_rows(source, table)
            if table in REQUIRED_SOURCE_TABLES and cursor is None:
                raise ValueError(f"SQLite database is missing required table {table!r}.")
            source_counts[table] = 0 if cursor is None else sum(1 for _ in cursor)

        ensure_destination_empty()
        init_db()
        with get_db() as destination:
            for table in TABLE_COLUMNS:
                count = destination.execute(
                    f"SELECT COUNT(*) AS count FROM {table}"
                ).fetchone()["count"]
                if count:
                    raise RuntimeError(
                        f"Destination table {table!r} is not empty; no rows were migrated."
                    )

            for table, columns in TABLE_COLUMNS.items():
                cursor = source_rows(source, table)
                if cursor is None:
                    continue
                quoted_columns = ", ".join(f'"{column}"' for column in columns)
                placeholders = ", ".join("?" for _ in columns)
                insert = f'INSERT INTO "{table}" ({quoted_columns}) VALUES ({placeholders})'
                while batch := cursor.fetchmany(500):
                    destination.executemany(
                        insert,
                        [
                            tuple(row_values(table, row)[column] for column in columns)
                            for row in batch
                        ],
                    )

            for table in IDENTITY_TABLES:
                destination.execute(
                    f"""SELECT setval(
                            pg_get_serial_sequence('{table}', 'id'),
                            COALESCE(MAX(id), 1),
                            MAX(id) IS NOT NULL
                        ) FROM {table}"""
                )

            for table, expected in source_counts.items():
                actual = destination.execute(
                    f"SELECT COUNT(*) AS count FROM {table}"
                ).fetchone()["count"]
                if actual != expected:
                    raise RuntimeError(
                        f"Row-count check failed for {table!r}: expected {expected}, found {actual}."
                    )
    finally:
        source.close()

    return backup_path, source_counts


def main():
    parser = argparse.ArgumentParser(
        description="Back up the local SQLite database and copy its records to PostgreSQL."
    )
    parser.add_argument("--sqlite", type=Path, default=DB_PATH)
    args = parser.parse_args()

    backup_path, counts = migrate(args.sqlite)
    print(f"SQLite backup created at: {backup_path}")
    for table, count in counts.items():
        print(f"{table}: {count} rows")
    print("Migration completed; the source SQLite database was not changed.")


if __name__ == "__main__":
    main()
