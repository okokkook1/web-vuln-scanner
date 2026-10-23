from __future__ import annotations

import sqlite3
from pathlib import Path

from vulnscan.db import SCHEMA_VERSION, Database, finding_fingerprint


def test_init_migrates_pre_fingerprint_database(tmp_path: Path):
    path = tmp_path / "legacy.db"
    fingerprint = "rule-legacy|GET|example.com|/legacy|"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE findings (
                id INTEGER NOT NULL PRIMARY KEY,
                scan_id VARCHAR NOT NULL,
                rule_id VARCHAR NOT NULL,
                title VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                confidence VARCHAR NOT NULL,
                url VARCHAR NOT NULL,
                method VARCHAR NOT NULL,
                parameter VARCHAR,
                category VARCHAR NOT NULL,
                description VARCHAR NOT NULL,
                evidence_json VARCHAR NOT NULL,
                remediation VARCHAR NOT NULL,
                refs_json VARCHAR NOT NULL,
                created_at DATETIME NOT NULL
            );
            CREATE TABLE finding_review_states (
                fingerprint VARCHAR NOT NULL PRIMARY KEY,
                status VARCHAR NOT NULL,
                note VARCHAR NOT NULL,
                updated_by VARCHAR NOT NULL,
                updated_at DATETIME NOT NULL
            );
            CREATE TABLE finding_review_state_events (
                id INTEGER NOT NULL PRIMARY KEY,
                fingerprint VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                note VARCHAR NOT NULL,
                updated_by VARCHAR NOT NULL,
                created_at DATETIME NOT NULL
            );
            INSERT INTO findings (
                id, scan_id, rule_id, title, severity, confidence, url,
                method, parameter, category, description, evidence_json,
                remediation, refs_json, created_at
            ) VALUES (
                1, 'scan_legacy', 'rule-legacy', 'legacy finding', 'high', 'high',
                'https://example.com/legacy', 'GET', NULL, '測試', '測試',
                '{"detail": "legacy"}', '修正', '{}', '2026-01-01 00:00:00'
            );
            INSERT INTO finding_review_states (
                fingerprint, status, note, updated_by, updated_at
            ) VALUES (
                'rule-legacy|GET|example.com|/legacy|',
                'confirmed', '舊版確認', 'legacy-user', '2026-01-01 00:00:00'
            );
            INSERT INTO finding_review_state_events (
                id, fingerprint, status, note, updated_by, created_at
            ) VALUES (
                1, 'rule-legacy|GET|example.com|/legacy|',
                'confirmed', '舊版確認', 'legacy-user', '2026-01-01 00:00:00'
            );
            PRAGMA user_version = 1;
            """
        )

    db = Database(path)
    db.init()

    with sqlite3.connect(path) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        finding_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(findings)")
        }
        state_columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(finding_review_states)")
        }
        event_columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(finding_review_state_events)"
            )
        }

    assert version == SCHEMA_VERSION
    assert "fingerprint" in finding_columns
    assert {"severity", "evidence_hash", "expires_at"} <= state_columns
    assert "expires_at" in event_columns

    view = db.get_finding_view(1)
    assert view is not None
    assert finding_fingerprint(view) == fingerprint
    assert view.review_status == "confirmed"
    assert view.review_note == "舊版確認"
    assert db.get_review_history(1)[0].expires_at is None

    history = db.fingerprint_history(fingerprint)
    assert history is not None
    assert history["occurrence_count"] == 1
    assert history["review"]["severity"] == "high"
    assert history["review"]["status"] == "confirmed"

    db.init()
    assert db.fingerprint_history(fingerprint)["occurrence_count"] == 1
