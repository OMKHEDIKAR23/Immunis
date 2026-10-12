"""SQLite provenance storage and cascading source revocation."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class ProvenanceStore:
    """Store source records, facts, and their derivation relationships."""

    def __init__(self, database_path: str | Path = ":memory:") -> None:
        self.connection = sqlite3.connect(str(database_path))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        """Create the database tables if they do not exist."""

        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sources (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                uri TEXT NOT NULL,
                trust TEXT NOT NULL,
                fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked INTEGER NOT NULL DEFAULT 0
                    CHECK (revoked IN (0, 1))
            );

            CREATE TABLE IF NOT EXISTS facts (
                id TEXT PRIMARY KEY,
                text TEXT NOT NULL,
                kind TEXT NOT NULL,
                trust TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked INTEGER NOT NULL DEFAULT 0
                    CHECK (revoked IN (0, 1))
            );

            CREATE TABLE IF NOT EXISTS derived (
                fact_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                parent_type TEXT NOT NULL
                    CHECK (parent_type IN ('source', 'fact')),
                PRIMARY KEY (fact_id, parent_id, parent_type),
                FOREIGN KEY (fact_id) REFERENCES facts(id)
            );

            CREATE INDEX IF NOT EXISTS idx_derived_parent
                ON derived(parent_id, parent_type);

            CREATE INDEX IF NOT EXISTS idx_facts_revoked
                ON facts(revoked);
            """
        )
        self.connection.commit()

    def add_source(
        self,
        source_id: str,
        kind: str,
        uri: str,
        trust: str = "untrusted",
    ) -> None:
        """Register a source such as a webpage or fixture email."""

        if trust not in {"trusted", "untrusted"}:
            raise ValueError("trust must be trusted or untrusted")

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO sources (id, kind, uri, trust)
                VALUES (?, ?, ?, ?)
                """,
                (source_id, kind, uri, trust),
            )

    def add_fact(
        self,
        fact_id: str,
        text: str,
        kind: str,
        trust: str,
        parent_ids: list[str],
        parent_type: str = "source",
    ) -> None:
        """
        Add a fact and record its provenance.

        Every fact must have at least one parent. A parent can be a source
        or an existing fact.
        """

        if trust not in {"trusted", "untrusted"}:
            raise ValueError("trust must be trusted or untrusted")

        if not parent_ids:
            raise ValueError("Every fact must have at least one parent.")

        if parent_type not in {"source", "fact"}:
            raise ValueError("parent_type must be source or fact")

        parent_table = "sources" if parent_type == "source" else "facts"

        for parent_id in parent_ids:
            row = self.connection.execute(
                f"SELECT id, revoked FROM {parent_table} WHERE id = ?",
                (parent_id,),
            ).fetchone()

            if row is None:
                raise ValueError(
                    f"Parent {parent_id!r} does not exist."
                )

            if row["revoked"]:
                raise ValueError(
                    f"Parent {parent_id!r} has been revoked."
                )

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO facts (id, text, kind, trust)
                VALUES (?, ?, ?, ?)
                """,
                (fact_id, text, kind, trust),
            )

            self.connection.executemany(
                """
                INSERT INTO derived (fact_id, parent_id, parent_type)
                VALUES (?, ?, ?)
                """,
                [
                    (fact_id, parent_id, parent_type)
                    for parent_id in parent_ids
                ],
            )

    def revoke_source(self, source_id: str) -> list[str]:
        """
        Revoke a source and recursively revoke facts derived from it.

        Returns the IDs of facts newly revoked by this operation.
        """

        source = self.connection.execute(
            "SELECT id FROM sources WHERE id = ?",
            (source_id,),
        ).fetchone()

        if source is None:
            raise ValueError(f"Unknown source: {source_id}")

        rows = self.connection.execute(
            """
            WITH RECURSIVE affected(fact_id) AS (
                SELECT fact_id
                FROM derived
                WHERE parent_id = ? AND parent_type = 'source'

                UNION

                SELECT d.fact_id
                FROM derived AS d
                JOIN affected AS a ON d.parent_id = a.fact_id
                WHERE d.parent_type = 'fact'
            )
            SELECT DISTINCT fact_id FROM affected
            """,
            (source_id,),
        ).fetchall()

        affected_ids = [row["fact_id"] for row in rows]

        with self.connection:
            self.connection.execute(
                "UPDATE sources SET revoked = 1 WHERE id = ?",
                (source_id,),
            )

            if affected_ids:
                placeholders = ",".join("?" for _ in affected_ids)
                self.connection.execute(
                    f"""
                    UPDATE facts
                    SET revoked = 1
                    WHERE id IN ({placeholders})
                    """,
                    affected_ids,
                )

        return affected_ids

    def get_fact(self, fact_id: str) -> dict[str, Any] | None:
        """Return a fact only if it is active and has active ancestry."""

        row = self.connection.execute(
            """
            SELECT id, text, kind, trust, created_at, revoked
            FROM facts
            WHERE id = ? AND revoked = 0
            """,
            (fact_id,),
        ).fetchone()

        if row is None:
            return None

        # Defend retrieval against incomplete or inconsistent revocation.
        ancestry = self.connection.execute(
            """
            WITH RECURSIVE parents(parent_id, parent_type) AS (
                SELECT parent_id, parent_type
                FROM derived
                WHERE fact_id = ?

                UNION

                SELECT d.parent_id, d.parent_type
                FROM derived AS d
                JOIN parents AS p
                  ON d.fact_id = p.parent_id
                WHERE p.parent_type = 'fact'
            )
            SELECT parent_id
            FROM parents
            WHERE parent_type = 'source'
            """,
            (fact_id,),
        ).fetchall()

        for parent in ancestry:
            source_row = self.connection.execute(
                """
                SELECT revoked FROM sources WHERE id = ?
                """,
                (parent["parent_id"],),
            ).fetchone()

            if source_row is None or source_row["revoked"]:
                return None

        return dict(row)

    def list_active_facts(self) -> list[dict[str, Any]]:
        """List facts that remain retrievable after revocation."""

        rows = self.connection.execute(
            "SELECT id FROM facts WHERE revoked = 0 ORDER BY id"
        ).fetchall()

        active: list[dict[str, Any]] = []

        for row in rows:
            fact = self.get_fact(row["id"])
            if fact is not None:
                active.append(fact)

        return active

    def close(self) -> None:
        """Close the SQLite connection."""

        self.connection.close()