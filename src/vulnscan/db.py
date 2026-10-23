from __future__ import annotations

import contextlib
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import event, func
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine, select

from .models import (
    REVIEW_STATUSES,
    Endpoint,
    EndpointRecord,
    Finding,
    FindingRecord,
    FindingReview,
    FindingReviewEvent,
    FindingReviewState,
    FindingReviewStateEvent,
    FindingView,
    Scan,
    ScanBaseline,
    Suppression,
    utcnow,
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


SCHEMA_VERSION = 3
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = {
    "info": "資訊",
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "嚴重",
}


def scan_target_key(targets: list[str]) -> str:
    normalized = sorted(
        {
            str(item).strip().rstrip("/")
            for item in targets
            if str(item).strip()
        }
    )
    return hashlib.sha256("|".join(normalized).encode("utf-8")).hexdigest()


def _targets_match(first: Scan, second: Scan) -> bool:
    first_targets = set(_loads(first.targets_json, []))
    second_targets = set(_loads(second.targets_json, []))
    if first_targets & second_targets:
        return True
    first_hosts = {
        urlsplit(target).hostname.lower()
        for target in first_targets
        if urlsplit(target).hostname
    }
    second_hosts = {
        urlsplit(target).hostname.lower()
        for target in second_targets
        if urlsplit(target).hostname
    }
    return bool(first_hosts & second_hosts)


def _fingerprint_parts(
    rule_id: str,
    method: str,
    url: str,
    parameter: str | None,
) -> str:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    return f"{rule_id}|{method.upper()}|{host}|{path}|{parameter or ''}"


def finding_fingerprint(item: FindingRecord | FindingView) -> str:
    record = item.record if isinstance(item, FindingView) else item
    stored = getattr(record, "fingerprint", "") or ""
    if stored:
        return stored
    return _fingerprint_parts(
        record.rule_id,
        record.method,
        record.url,
        record.parameter,
    )


VOLATILE_EVIDENCE_KEYS = frozenset(
    {
        "callback_url",
        "days_left",
        "hit_count",
        "not_after",
        "position",
    }
)


def _normalized_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalized_evidence(item)
            for key, item in value.items()
            if key not in VOLATILE_EVIDENCE_KEYS
        }
    if isinstance(value, list):
        return [_normalized_evidence(item) for item in value]
    return value


def _evidence_hash(value: str | None) -> str:
    raw = value or "{}"
    with contextlib.suppress(TypeError, json.JSONDecodeError):
        raw = json.dumps(
            _normalized_evidence(json.loads(raw)),
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{path.as_posix()}",
            connect_args={"check_same_thread": False, "timeout": 10},
        )
        self._install_pragmas(self.engine)

    @staticmethod
    def _install_pragmas(engine: Engine) -> None:
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    def init(self) -> None:
        SQLModel.metadata.create_all(self.engine)
        self._migrate_schema()
        self._backfill_finding_fingerprints()
        self._backfill_review_states()
        self._backfill_review_policy_fields()

    def _migrate_schema(self) -> None:
        """Apply additive, idempotent SQLite migrations.

        ``create_all`` handles new databases and new tables. Existing tables
        need explicit columns, so ``PRAGMA user_version`` tracks the applied
        schema while each step also checks the current table shape.
        """
        with self.engine.begin() as conn:
            version = int(conn.exec_driver_sql("PRAGMA user_version").scalar() or 0)
            if version >= SCHEMA_VERSION:
                return
            self._ensure_column(conn, "findings", "fingerprint", "TEXT DEFAULT ''")
            self._ensure_column(
                conn,
                "finding_review_states",
                "severity",
                "TEXT DEFAULT ''",
            )
            self._ensure_column(
                conn,
                "finding_review_states",
                "evidence_hash",
                "TEXT DEFAULT ''",
            )
            self._ensure_column(
                conn,
                "finding_review_states",
                "expires_at",
                "DATETIME",
            )
            self._ensure_column(
                conn,
                "finding_review_state_events",
                "expires_at",
                "DATETIME",
            )
            conn.exec_driver_sql(
                "CREATE INDEX IF NOT EXISTS ix_findings_fingerprint "
                "ON findings (fingerprint)"
            )
            conn.exec_driver_sql(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _ensure_column(conn: Any, table: str, column: str, ddl: str) -> None:
        rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
        if column not in {row[1] for row in rows}:
            conn.exec_driver_sql(
                f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"
            )

    def _backfill_finding_fingerprints(self) -> None:
        with self.session() as session:
            rows = session.exec(
                select(FindingRecord).where(
                    (FindingRecord.fingerprint == "")
                    | (FindingRecord.fingerprint.is_(None))
                )
            ).all()
            if not rows:
                return
            for row in rows:
                row.fingerprint = _fingerprint_parts(
                    row.rule_id,
                    row.method,
                    row.url,
                    row.parameter,
                )
                session.add(row)
            session.commit()

    def _backfill_review_states(self) -> None:
        """Migrate the old per-finding review rows to fingerprint state.

        The old tables remain in place for compatibility. Cross-scan state is
        only seeded when the new state table is empty, so user edits are never
        overwritten on later starts.
        """
        with self.session() as session:
            if session.exec(select(FindingReviewState)).first():
                return
            reviews = session.exec(select(FindingReview)).all()
            findings = {
                item.id: item
                for item in session.exec(select(FindingRecord)).all()
                if item.id is not None
            }
            latest: dict[str, tuple[FindingReview, FindingRecord]] = {}
            for review in reviews:
                finding = findings.get(review.finding_id)
                if not finding:
                    continue
                fingerprint = finding_fingerprint(finding)
                current = latest.get(fingerprint)
                if current is None or review.updated_at > current[0].updated_at:
                    latest[fingerprint] = (review, finding)
            for fingerprint, (review, finding) in latest.items():
                session.add(
                    FindingReviewState(
                        fingerprint=fingerprint,
                        status=review.status,
                        note=review.note,
                        updated_by=review.updated_by,
                        updated_at=review.updated_at,
                        severity=finding.severity,
                        evidence_hash=_evidence_hash(finding.evidence_json),
                    )
                )
            legacy_events = session.exec(
                select(FindingReviewEvent).order_by(
                    FindingReviewEvent.created_at.asc()
                )
            ).all()
            for event in legacy_events:
                finding = findings.get(event.finding_id)
                if not finding:
                    continue
                session.add(
                    FindingReviewStateEvent(
                        fingerprint=finding_fingerprint(finding),
                        status=event.status,
                        note=event.note,
                        updated_by=event.updated_by,
                        created_at=event.created_at,
                    )
                )
            session.commit()

    def _backfill_review_policy_fields(self) -> None:
        """Seed policy baselines for states created before v0.22."""
        with self.session() as session:
            states = session.exec(
                select(FindingReviewState).where(
                    (FindingReviewState.severity == "")
                    | (FindingReviewState.evidence_hash == "")
                )
            ).all()
            if not states:
                return
            rows = session.exec(
                select(FindingRecord).order_by(FindingRecord.created_at.asc())
            ).all()
            latest: dict[str, FindingRecord] = {}
            for row in rows:
                if row.fingerprint:
                    latest[row.fingerprint] = row
            for state in states:
                finding = latest.get(state.fingerprint)
                if not finding:
                    continue
                state.severity = finding.severity
                state.evidence_hash = _evidence_hash(finding.evidence_json)
                session.add(state)
            session.commit()

    def session(self) -> Session:
        return Session(self.engine)

    def mark_interrupted(self) -> int:
        """Mark scans that were in flight when the server stopped."""
        changed = 0
        with self.session() as session:
            scans = session.exec(
                select(Scan).where(Scan.status.in_(["queued", "running"]))
            ).all()
            for scan in scans:
                scan.status = "failed"
                scan.error = "服務重新啟動，掃描已中斷"
                scan.message = scan.error
                scan.finished_at = utcnow()
                session.add(scan)
                changed += 1
            session.commit()
        return changed

    def create_scan(self, scan: Scan) -> Scan:
        with self.session() as session:
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan

    def update_scan(self, scan_id: str, **fields: Any) -> None:
        with self.session() as session:
            scan = session.get(Scan, scan_id)
            if not scan:
                return
            for key, value in fields.items():
                setattr(scan, key, value)
            session.add(scan)
            session.commit()

    def get_scan(self, scan_id: str) -> Scan | None:
        with self.session() as session:
            return session.get(Scan, scan_id)

    def list_scans(self, limit: int = 50) -> list[Scan]:
        with self.session() as session:
            return list(
                session.exec(select(Scan).order_by(Scan.created_at.desc()).limit(limit)).all()
            )

    def recent_scans(self, limit: int = 8) -> list[Scan]:
        return self.list_scans(limit=limit)

    def add_findings(self, scan_id: str, findings: list[Finding]) -> int:
        if not findings:
            return 0
        now = utcnow()
        records = [
            FindingRecord(
                scan_id=scan_id,
                fingerprint=_fingerprint_parts(
                    f.rule_id,
                    f.method,
                    f.url,
                    f.parameter,
                ),
                rule_id=f.rule_id,
                title=f.title,
                severity=f.severity.value,
                confidence=f.confidence.value,
                url=f.url,
                method=f.method,
                parameter=f.parameter,
                category=f.category,
                description=f.description,
                evidence_json=_json(f.evidence),
                remediation=f.remediation,
                refs_json=_json(f.refs),
                created_at=now,
            )
            for f in findings
        ]
        with self.session() as session:
            session.add_all(records)
            for record in records:
                self._apply_review_policy(session, record)
            session.commit()
        return len(records)

    def _apply_review_policy(
        self,
        session: Session,
        record: FindingRecord,
    ) -> None:
        """Reopen a reviewed finding when its risk context changed."""
        fingerprint = finding_fingerprint(record)
        state = session.get(FindingReviewState, fingerprint)
        if state is None or state.status == "needs_review":
            return
        now = utcnow()
        reason = ""
        expires_at = _as_utc(state.expires_at)
        if state.status == "accepted_risk" and expires_at and expires_at <= now:
            reason = f"接受風險已於 {expires_at:%Y-%m-%d} 到期"
        if not reason and state.severity:
            old_rank = SEVERITY_RANK.get(state.severity, -1)
            new_rank = SEVERITY_RANK.get(record.severity, -1)
            if new_rank > old_rank:
                reason = (
                    "嚴重度由 "
                    f"{SEVERITY_NAMES.get(state.severity, state.severity)} 升為 "
                    f"{SEVERITY_NAMES.get(record.severity, record.severity)}"
                )
        if not reason and state.status == "false_positive":
            current_hash = _evidence_hash(record.evidence_json)
            if state.evidence_hash and state.evidence_hash != current_hash:
                reason = "誤報的證據內容已改變"
        if not reason:
            return
        state.status = "needs_review"
        state.note = f"自動重開：{reason}"
        state.updated_by = "system"
        state.updated_at = now
        state.severity = record.severity
        state.evidence_hash = _evidence_hash(record.evidence_json)
        state.expires_at = None
        session.add(state)
        session.add(
            FindingReviewStateEvent(
                fingerprint=fingerprint,
                status="needs_review",
                note=state.note,
                updated_by="system",
            )
        )

    def save_endpoints(self, scan_id: str, endpoints: list[Endpoint]) -> None:
        if not endpoints:
            return
        records = [
            EndpointRecord(
                scan_id=scan_id,
                url=e.url,
                method=e.method,
                params_json=_json([p.model_dump() for p in e.params]),
                source=e.source,
                depth=e.depth,
            )
            for e in endpoints[:5000]
        ]
        with self.session() as session:
            session.add_all(records)
            session.commit()

    def suppression_map(self) -> dict[str, Suppression]:
        with self.session() as session:
            rows = session.exec(select(Suppression)).all()
        return {row.fingerprint: row for row in rows}

    def _review_map(
        self,
        rows: list[FindingRecord],
    ) -> dict[str, FindingReviewState]:
        fingerprints = {finding_fingerprint(row) for row in rows}
        if not fingerprints:
            return {}
        reviews: list[FindingReviewState] = []
        with self.session() as session:
            values = sorted(fingerprints)
            for start in range(0, len(values), 400):
                chunk = values[start : start + 400]
                reviews.extend(
                    session.exec(
                        select(FindingReviewState).where(
                            FindingReviewState.fingerprint.in_(chunk)
                        )
                    ).all()
                )
        return {review.fingerprint: review for review in reviews}

    def _views(
        self,
        rows: list[FindingRecord],
        suppressions: dict[str, Suppression],
    ) -> list[FindingView]:
        reviews = self._review_map(rows)
        views = []
        for row in rows:
            fingerprint = finding_fingerprint(row)
            suppression = suppressions.get(fingerprint)
            review = reviews.get(fingerprint)
            views.append(
                FindingView(
                    record=row,
                    suppressed=suppression is not None,
                    suppression_id=suppression.id if suppression else None,
                    suppression_reason=suppression.reason if suppression else None,
                    suppression_created_by=suppression.created_by if suppression else None,
                    suppression_created_at=suppression.created_at if suppression else None,
                    review_status=review.status if review else "needs_review",
                    review_note=review.note if review else "",
                    review_updated_by=review.updated_by if review else None,
                    review_updated_at=review.updated_at if review else None,
                    review_expires_at=review.expires_at if review else None,
                )
            )
        return views

    def get_findings(
        self,
        scan_id: str,
        *,
        severity: str | None = None,
        confidence: str | None = None,
        category: str | None = None,
        review_status: str | None = None,
        query: str | None = None,
        limit: int = 1000,
        include_suppressed: bool = False,
    ) -> list[FindingView]:
        with self.session() as session:
            stmt = select(FindingRecord).where(FindingRecord.scan_id == scan_id)
            if severity:
                stmt = stmt.where(FindingRecord.severity == severity)
            if confidence:
                stmt = stmt.where(FindingRecord.confidence == confidence)
            if category:
                stmt = stmt.where(FindingRecord.category == category)
            if query:
                like = f"%{query}%"
                stmt = stmt.where(
                    (FindingRecord.title.like(like))
                    | (FindingRecord.url.like(like))
                    | (FindingRecord.parameter.like(like))
                    | (FindingRecord.rule_id.like(like))
                )
            if not review_status:
                stmt = stmt.limit(limit)
            rows = list(session.exec(stmt).all())
        views = self._views(rows, self.suppression_map())
        if review_status:
            views = [
                item for item in views if item.review_status == review_status
            ]
        if not include_suppressed:
            views = [item for item in views if not item.suppressed]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        views.sort(key=lambda item: (rank.get(item.severity, 9), item.rule_id, item.url))
        return views[:limit]

    def get_finding_view(self, finding_id: int) -> FindingView | None:
        with self.session() as session:
            record = session.get(FindingRecord, finding_id)
        if not record:
            return None
        fingerprint = finding_fingerprint(record)
        suppression = self.suppression_map().get(fingerprint)
        review = self._review_map([record]).get(fingerprint)
        return FindingView(
            record=record,
            suppressed=suppression is not None,
            suppression_id=suppression.id if suppression else None,
            suppression_reason=suppression.reason if suppression else None,
            suppression_created_by=suppression.created_by if suppression else None,
            suppression_created_at=suppression.created_at if suppression else None,
            review_status=review.status if review else "needs_review",
            review_note=review.note if review else "",
            review_updated_by=review.updated_by if review else None,
            review_updated_at=review.updated_at if review else None,
            review_expires_at=review.expires_at if review else None,
        )

    def set_finding_review(
        self,
        finding_id: int,
        status: str,
        note: str = "",
        updated_by: str = "local",
        expires_at: datetime | None = None,
    ) -> FindingReviewState:
        if status not in REVIEW_STATUSES:
            raise ValueError("未知的弱點驗證狀態")
        cleaned_note = note.strip()[:4000]
        if status in ("false_positive", "accepted_risk") and not cleaned_note:
            raise ValueError("誤報或接受風險必須填寫備註")
        expiry = _as_utc(expires_at) if status == "accepted_risk" else None
        with self.session() as session:
            finding = session.get(FindingRecord, finding_id)
            if finding is None:
                raise ValueError("找不到弱點")
            fingerprint = finding.fingerprint or finding_fingerprint(finding)
            latest = session.exec(
                select(FindingRecord)
                .where(FindingRecord.fingerprint == fingerprint)
                .order_by(
                    FindingRecord.created_at.desc(),
                    FindingRecord.id.desc(),
                )
            ).first()
            baseline = latest or finding
            review = session.get(FindingReviewState, fingerprint)
            if review is None:
                review = FindingReviewState(fingerprint=fingerprint)
            review.status = status
            review.note = cleaned_note
            review.updated_by = updated_by.strip() or "local"
            review.updated_at = utcnow()
            review.severity = baseline.severity
            review.evidence_hash = _evidence_hash(baseline.evidence_json)
            review.expires_at = expiry
            event = FindingReviewStateEvent(
                fingerprint=fingerprint,
                status=review.status,
                note=review.note,
                updated_by=review.updated_by,
                expires_at=expiry,
            )
            session.add(review)
            session.add(event)
            session.commit()
            session.refresh(review)
            return review

    def set_review_many(
        self,
        finding_ids: list[int],
        status: str,
        note: str = "",
        updated_by: str = "local",
        expires_at: datetime | None = None,
    ) -> int:
        if status not in REVIEW_STATUSES:
            raise ValueError("未知的弱點驗證狀態")
        cleaned_note = note.strip()[:4000]
        if status in ("false_positive", "accepted_risk") and not cleaned_note:
            raise ValueError("誤報或接受風險必須填寫備註")
        changed = 0
        for finding_id in finding_ids:
            try:
                self.set_finding_review(
                    finding_id,
                    status,
                    cleaned_note,
                    updated_by,
                    expires_at,
                )
                changed += 1
            except ValueError:
                continue
        return changed

    def get_review_history(
        self,
        finding_id: int,
        limit: int = 100,
    ) -> list[FindingReviewStateEvent]:
        with self.session() as session:
            finding = session.get(FindingRecord, finding_id)
            if finding is None:
                return []
            fingerprint = finding.fingerprint
            return list(
                session.exec(
                    select(FindingReviewStateEvent)
                    .where(FindingReviewStateEvent.fingerprint == fingerprint)
                    .order_by(
                        FindingReviewStateEvent.created_at.desc(),
                        FindingReviewStateEvent.id.desc(),
                    )
                    .limit(limit)
                ).all()
            )

    def review_histories(
        self,
        scan_id: str,
    ) -> dict[int, list[dict[str, Any]]]:
        with self.session() as session:
            findings = session.exec(
                select(FindingRecord).where(FindingRecord.scan_id == scan_id)
            ).all()
            id_to_fingerprint = {
                item.id: item.fingerprint
                for item in findings
                if item.id is not None and item.fingerprint
            }
            fingerprints = set(id_to_fingerprint.values())
            if not fingerprints:
                return {}
            events = session.exec(
                select(FindingReviewStateEvent)
                .where(FindingReviewStateEvent.fingerprint.in_(fingerprints))
                .order_by(
                    FindingReviewStateEvent.created_at.desc(),
                    FindingReviewStateEvent.id.desc(),
                )
            ).all()
        by_fingerprint: dict[str, list[dict[str, Any]]] = {}
        for item in events:
            by_fingerprint.setdefault(item.fingerprint, []).append(
                {
                    "status": item.status,
                    "note": item.note,
                    "updated_by": item.updated_by,
                    "created_at": item.created_at.isoformat(),
                    "expires_at": (
                        item.expires_at.isoformat() if item.expires_at else None
                    ),
                }
            )
        return {
            finding_id: by_fingerprint.get(fingerprint, [])
            for finding_id, fingerprint in id_to_fingerprint.items()
        }

    def fingerprint_history(self, fingerprint: str) -> dict[str, Any] | None:
        with self.session() as session:
            rows = list(
                session.exec(
                    select(FindingRecord)
                    .where(FindingRecord.fingerprint == fingerprint)
                    .order_by(
                        FindingRecord.created_at.asc(),
                        FindingRecord.id.asc(),
                    )
                ).all()
            )
            if not rows:
                return None
            state = session.get(FindingReviewState, fingerprint)
            events = list(
                session.exec(
                    select(FindingReviewStateEvent)
                    .where(FindingReviewStateEvent.fingerprint == fingerprint)
                    .order_by(
                        FindingReviewStateEvent.created_at.desc(),
                        FindingReviewStateEvent.id.desc(),
                    )
                ).all()
            )
            suppression = session.exec(
                select(Suppression).where(Suppression.fingerprint == fingerprint)
            ).first()
            scan_ids = {row.scan_id for row in rows}
            scans = {
                scan.id: scan
                for scan in session.exec(
                    select(Scan).where(Scan.id.in_(scan_ids))
                ).all()
            }
        severity_counts: dict[str, int] = {}
        for row in rows:
            severity_counts[row.severity] = (
                severity_counts.get(row.severity, 0) + 1
            )
        latest = rows[-1]
        return {
            "fingerprint": fingerprint,
            "occurrences": [
                {"finding": row, "scan": scans.get(row.scan_id)}
                for row in rows
            ],
            "events": [
                {
                    "status": item.status,
                    "note": item.note,
                    "updated_by": item.updated_by,
                    "created_at": item.created_at,
                    "expires_at": item.expires_at,
                }
                for item in events
            ],
            "review": {
                "status": state.status if state else "needs_review",
                "note": state.note if state else "",
                "updated_by": state.updated_by if state else None,
                "updated_at": state.updated_at if state else None,
                "severity": state.severity if state else "",
                "expires_at": state.expires_at if state else None,
            },
            "suppression": (
                {
                    "reason": suppression.reason,
                    "created_by": suppression.created_by,
                    "created_at": suppression.created_at,
                }
                if suppression
                else None
            ),
            "title": latest.title,
            "rule_id": latest.rule_id,
            "method": latest.method,
            "url": latest.url,
            "parameter": latest.parameter,
            "latest_finding_id": latest.id,
            "latest_severity": latest.severity,
            "first_seen": rows[0].created_at,
            "last_seen": latest.created_at,
            "occurrence_count": len(rows),
            "scan_count": len(scan_ids),
            "severity_counts": severity_counts,
        }

    def review_workbench(
        self,
        *,
        status: str = "needs_review",
        severity: str | None = None,
        target: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        with self.session() as session:
            rows = list(
                session.exec(
                    select(FindingRecord).order_by(
                        FindingRecord.created_at.desc(),
                        FindingRecord.id.desc(),
                    )
                ).all()
            )
            scans = {
                scan.id: scan
                for scan in session.exec(select(Scan)).all()
            }
        groups: dict[str, dict[str, Any]] = {}
        for view in self._views(rows, self.suppression_map()):
            if view.suppressed:
                continue
            fingerprint = finding_fingerprint(view)
            scan = scans.get(view.scan_id)
            seen_at = _as_utc(scan.created_at if scan else view.created_at)
            targets = _loads(scan.targets_json, []) if scan else []
            known = groups.get(fingerprint)
            if known is None:
                groups[fingerprint] = {
                    "finding": view,
                    "fingerprint": fingerprint,
                    "occurrence_count": 1,
                    "scan_count": 1,
                    "scan_ids": {view.scan_id},
                    "first_seen": seen_at,
                    "last_seen": seen_at,
                    "targets": targets,
                }
                continue
            known["occurrence_count"] += 1
            if view.scan_id not in known["scan_ids"]:
                known["scan_ids"].add(view.scan_id)
                known["scan_count"] += 1
            if seen_at < known["first_seen"]:
                known["first_seen"] = seen_at
            if seen_at > known["last_seen"]:
                known["finding"] = view
                known["last_seen"] = seen_at
                known["targets"] = targets

        counts = {item: 0 for item in REVIEW_STATUSES}
        high_priority = 0
        now = utcnow()
        expired: list[dict[str, Any]] = []
        expiring: list[dict[str, Any]] = []
        for item in groups.values():
            view = item["finding"]
            counts[view.review_status] = counts.get(view.review_status, 0) + 1
            if (
                view.review_status == "needs_review"
                and view.severity in ("critical", "high")
            ):
                high_priority += 1
            expires = _as_utc(view.review_expires_at)
            if view.review_status != "accepted_risk" or not expires:
                continue
            seconds = (expires - now).total_seconds()
            if seconds <= 0:
                expired.append(item)
            elif seconds <= 30 * 24 * 60 * 60:
                expiring.append(item)

        filtered = []
        for item in groups.values():
            view = item["finding"]
            if status and status != "all" and view.review_status != status:
                continue
            if severity and view.severity != severity:
                continue
            if target and target not in item["targets"]:
                continue
            filtered.append(item)
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        def sort_key(item: dict[str, Any]) -> tuple[int, float, str]:
            seen = item["last_seen"]
            timestamp = (
                seen.timestamp()
                if seen.tzinfo is not None
                else seen.replace(tzinfo=UTC).timestamp()
            )
            return (
                rank.get(item["finding"].severity, 9),
                -timestamp,
                item["finding"].rule_id,
            )

        filtered.sort(key=sort_key)
        for item in expired:
            item["expiry_state"] = "expired"
        for item in expiring:
            item["expiry_state"] = "expiring"
        expired.sort(
            key=lambda item: _as_utc(item["finding"].review_expires_at)
            or now
        )
        expiring.sort(
            key=lambda item: _as_utc(item["finding"].review_expires_at)
            or now
        )
        targets = sorted(
            {
                value
                for scan in scans.values()
                for value in _loads(scan.targets_json, [])
            }
        )
        return {
            "rows": filtered[:limit],
            "counts": counts,
            "total_fingerprints": len(groups),
            "high_priority": high_priority,
            "expired_risks": expired,
            "expiring_risks": expiring,
            "targets": targets,
            "filters": {
                "status": status,
                "severity": severity or "",
                "target": target or "",
            },
        }

    def review_status_counts(
        self,
        scan_id: str | None = None,
        *,
        include_suppressed: bool = False,
    ) -> dict[str, int]:
        counts = {status: 0 for status in REVIEW_STATUSES}
        with self.session() as session:
            stmt = select(FindingRecord)
            if scan_id:
                stmt = stmt.where(FindingRecord.scan_id == scan_id)
            rows = list(session.exec(stmt).all())
        for item in self._views(rows, self.suppression_map()):
            if item.suppressed and not include_suppressed:
                continue
            counts[item.review_status] = counts.get(item.review_status, 0) + 1
        return counts

    def get_finding(self, finding_id: int) -> FindingRecord | None:
        with self.session() as session:
            return session.get(FindingRecord, finding_id)

    def count_findings(self, scan_id: str | None = None, *, include_suppressed: bool = False) -> int:
        with self.session() as session:
            stmt = select(FindingRecord)
            if scan_id:
                stmt = stmt.where(FindingRecord.scan_id == scan_id)
            rows = list(session.exec(stmt).all())
        views = self._views(rows, self.suppression_map())
        if not include_suppressed:
            views = [item for item in views if not item.suppressed]
        return len(views)

    def count_suppressed(self, scan_id: str | None = None) -> int:
        with self.session() as session:
            stmt = select(FindingRecord)
            if scan_id:
                stmt = stmt.where(FindingRecord.scan_id == scan_id)
            rows = list(session.exec(stmt).all())
        return sum(1 for item in self._views(rows, self.suppression_map()) if item.suppressed)

    def severity_counts(
        self, scan_id: str | None = None, *, include_suppressed: bool = False
    ) -> dict[str, int]:
        counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
        with self.session() as session:
            stmt = select(FindingRecord)
            if scan_id:
                stmt = stmt.where(FindingRecord.scan_id == scan_id)
            rows = list(session.exec(stmt).all())
        for item in self._views(rows, self.suppression_map()):
            if item.suppressed and not include_suppressed:
                continue
            counts[item.severity] = counts.get(item.severity, 0) + 1
        return counts

    def category_counts(
        self, scan_id: str, *, include_suppressed: bool = False
    ) -> list[tuple[str, int]]:
        with self.session() as session:
            rows = list(
                session.exec(
                    select(FindingRecord).where(FindingRecord.scan_id == scan_id)
                ).all()
            )
        counts: dict[str, int] = {}
        for item in self._views(rows, self.suppression_map()):
            if item.suppressed and not include_suppressed:
                continue
            key = item.category or "其他"
            counts[key] = counts.get(key, 0) + 1
        return sorted(counts.items(), key=lambda item: item[1], reverse=True)

    def add_suppression(
        self,
        item: FindingRecord | FindingView,
        *,
        reason: str,
        created_by: str = "local",
    ) -> Suppression:
        record = item.record if isinstance(item, FindingView) else item
        fingerprint = finding_fingerprint(record)
        parsed = urlsplit(record.url)
        with self.session() as session:
            existing = session.exec(
                select(Suppression).where(Suppression.fingerprint == fingerprint)
            ).first()
            if existing:
                existing.reason = reason
                existing.created_by = created_by
                existing.created_at = utcnow()
                session.add(existing)
                session.commit()
                session.refresh(existing)
                return existing
            suppression = Suppression(
                fingerprint=fingerprint,
                rule_id=record.rule_id,
                host=(parsed.hostname or "").lower(),
                path=parsed.path or "/",
                method=record.method.upper(),
                parameter=record.parameter or "",
                reason=reason,
                created_by=created_by,
            )
            session.add(suppression)
            session.commit()
            session.refresh(suppression)
            return suppression

    def remove_suppression(self, suppression_id: int) -> None:
        with self.session() as session:
            suppression = session.get(Suppression, suppression_id)
            if suppression:
                session.delete(suppression)
                session.commit()

    def remove_suppression_by_fingerprint(self, fingerprint: str) -> None:
        with self.session() as session:
            suppression = session.exec(
                select(Suppression).where(Suppression.fingerprint == fingerprint)
            ).first()
            if suppression:
                session.delete(suppression)
                session.commit()

    def list_suppressions(self) -> list[Suppression]:
        with self.session() as session:
            return list(
                session.exec(select(Suppression).order_by(Suppression.created_at.desc())).all()
            )

    def list_previous_scans(self, scan_id: str, limit: int = 10) -> list[Scan]:
        current = self.get_scan(scan_id)
        if not current:
            return []
        result: list[Scan] = []
        with self.session() as session:
            scans = session.exec(
                select(Scan)
                .where(
                    Scan.id != current.id,
                    Scan.status.in_(["completed", "cancelled"]),
                    Scan.created_at < current.created_at,
                )
                .order_by(Scan.created_at.desc())
                .limit(200)
            ).all()
        for scan in scans:
            if _targets_match(current, scan):
                result.append(scan)
            if len(result) >= limit:
                break
        return result

    def can_compare_scans(self, current_id: str, previous_id: str) -> bool:
        current = self.get_scan(current_id)
        previous = self.get_scan(previous_id)
        if not current or not previous or current.id == previous.id:
            return False
        if previous.status not in ("completed", "cancelled"):
            return False
        if previous.created_at >= current.created_at:
            return False
        return _targets_match(current, previous)

    def get_baseline_for_scan(self, scan: Scan) -> Scan | None:
        key = scan_target_key(_loads(scan.targets_json, []))
        with self.session() as session:
            baseline = session.get(ScanBaseline, key)
            if not baseline:
                return None
            return session.get(Scan, baseline.scan_id)

    def set_baseline(
        self,
        scan_id: str,
        created_by: str = "local",
    ) -> ScanBaseline | None:
        scan = self.get_scan(scan_id)
        if not scan or scan.status not in ("completed", "cancelled"):
            return None
        key = scan_target_key(_loads(scan.targets_json, []))
        with self.session() as session:
            baseline = session.get(ScanBaseline, key)
            if baseline is None:
                baseline = ScanBaseline(target_key=key)
            baseline.targets_json = scan.targets_json
            baseline.scan_id = scan.id
            baseline.created_by = created_by.strip() or "local"
            baseline.created_at = utcnow()
            session.add(baseline)
            session.commit()
            session.refresh(baseline)
            return baseline

    def remove_baseline_for_scan(self, scan_id: str) -> bool:
        scan = self.get_scan(scan_id)
        if not scan:
            return False
        key = scan_target_key(_loads(scan.targets_json, []))
        with self.session() as session:
            baseline = session.get(ScanBaseline, key)
            if not baseline:
                return False
            session.delete(baseline)
            session.commit()
            return True

    def target_trends(
        self,
        *,
        scan_limit: int = 200,
        scans_per_group: int = 8,
    ) -> list[dict[str, Any]]:
        with self.session() as session:
            scans = list(
                session.exec(
                    select(Scan)
                    .where(Scan.status.in_(["completed", "cancelled"]))
                    .order_by(Scan.created_at.asc())
                    .limit(scan_limit)
                ).all()
            )
        groups: dict[str, list[Scan]] = {}
        for scan in scans:
            key = scan_target_key(_loads(scan.targets_json, []))
            groups.setdefault(key, []).append(scan)

        from .diff import compare_scans

        trends: list[dict[str, Any]] = []
        for key, group in groups.items():
            group.sort(key=lambda item: (item.created_at, item.id))
            series: list[dict[str, Any]] = []
            previous: Scan | None = None
            for scan in group[-(scans_per_group + 1):]:
                views = self.get_findings(
                    scan.id,
                    limit=5000,
                    include_suppressed=True,
                )
                active = [item for item in views if not item.suppressed]
                review_counts = {status: 0 for status in REVIEW_STATUSES}
                severity_counts: dict[str, int] = {}
                for item in active:
                    review_counts[item.review_status] = (
                        review_counts.get(item.review_status, 0) + 1
                    )
                    severity_counts[item.severity] = (
                        severity_counts.get(item.severity, 0) + 1
                    )
                if previous is None:
                    changes = {
                        "new": None,
                        "new_confirmed": None,
                        "new_needs_review": None,
                        "fixed": None,
                        "untested": None,
                        "reviewed_out": None,
                    }
                    previous_id = None
                else:
                    result = compare_scans(self, scan.id, previous.id)
                    changes = {
                        "new": result.summary["new"],
                        "new_confirmed": result.summary["new_confirmed"],
                        "new_needs_review": result.summary["new_needs_review"],
                        "fixed": result.summary["fixed"],
                        "untested": result.summary["untested"],
                        "reviewed_out": result.summary["reviewed_out"],
                    }
                    previous_id = previous.id
                series.append(
                    {
                        "scan": scan,
                        "findings": len(active),
                        "severity_counts": severity_counts,
                        "review_counts": review_counts,
                        "previous_id": previous_id,
                        **changes,
                    }
                )
                previous = scan
            latest = series[-1]
            trends.append(
                {
                    "target_key": key,
                    "targets": _loads(group[-1].targets_json, []),
                    "scan_count": len(group),
                    "latest": group[-1],
                    "latest_findings": latest["findings"],
                    "latest_severity": latest["severity_counts"],
                    "open_high": (
                        latest["severity_counts"].get("critical", 0)
                        + latest["severity_counts"].get("high", 0)
                    ),
                    "series": series[-scans_per_group:],
                }
            )
        trends.sort(key=lambda item: item["latest"].created_at, reverse=True)
        return trends

    def dashboard(self) -> dict[str, Any]:
        with self.session() as session:
            total_scans = int(session.exec(select(func.count(Scan.id))).one() or 0)
            running = int(
                session.exec(
                    select(func.count(Scan.id)).where(Scan.status == "running")
                ).one()
                or 0
            )
        return {
            "total_scans": total_scans,
            "running": running,
            "total_findings": self.count_findings(),
            "suppressed_findings": self.count_suppressed(),
            "severity": self.severity_counts(),
            "review_status": self.review_status_counts(),
            "recent": self.recent_scans(8),
        }

    def delete_scan(self, scan_id: str) -> None:
        with self.session() as session:
            scan = session.get(Scan, scan_id)
            if scan:
                findings = session.exec(
                    select(FindingRecord).where(FindingRecord.scan_id == scan_id)
                ).all()
                finding_ids = [item.id for item in findings if item.id is not None]
                if finding_ids:
                    for review in session.exec(
                        select(FindingReview).where(
                            FindingReview.finding_id.in_(finding_ids)
                        )
                    ).all():
                        session.delete(review)
                    for event in session.exec(
                        select(FindingReviewEvent).where(
                            FindingReviewEvent.finding_id.in_(finding_ids)
                        )
                    ).all():
                        session.delete(event)
                for record in findings:
                    session.delete(record)
                for record in session.exec(
                    select(EndpointRecord).where(EndpointRecord.scan_id == scan_id)
                ).all():
                    session.delete(record)
                for baseline in session.exec(
                    select(ScanBaseline).where(ScanBaseline.scan_id == scan_id)
                ).all():
                    session.delete(baseline)
                session.flush()
                session.delete(scan)
                session.commit()


def finding_to_dict(item: FindingRecord | FindingView) -> dict[str, Any]:
    view = item if isinstance(item, FindingView) else None
    record = view.record if view else item
    data = {
        "id": record.id,
        "fingerprint": record.fingerprint,
        "rule_id": record.rule_id,
        "title": record.title,
        "severity": record.severity,
        "confidence": record.confidence,
        "url": record.url,
        "method": record.method,
        "parameter": record.parameter,
        "category": record.category,
        "description": record.description,
        "evidence": _loads(record.evidence_json, {}),
        "remediation": record.remediation,
        "refs": _loads(record.refs_json, {}),
    }
    if view:
        data["suppressed"] = view.suppressed
        data["suppression_reason"] = view.suppression_reason
        data["review_status"] = view.review_status
        data["review_note"] = view.review_note
        data["review_updated_by"] = view.review_updated_by
        data["review_updated_at"] = (
            view.review_updated_at.isoformat()
            if view.review_updated_at
            else None
        )
        data["review_expires_at"] = (
            view.review_expires_at.isoformat()
            if view.review_expires_at
            else None
        )
    return data
