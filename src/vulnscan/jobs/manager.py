from __future__ import annotations

import asyncio
import contextlib
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..db import Database
from ..engine import ScanEngine
from ..http import ScanCancelled
from ..models import AuthConfig, ScanConfig, utcnow


@dataclass
class JobState:
    scan_id: str
    status: str = "queued"
    phase: str = "排隊中"
    phase_key: str = "validate"
    progress: int = 0
    message: str = ""
    stats: dict[str, Any] = field(default_factory=dict)
    logs: deque[dict[str, str]] = field(default_factory=lambda: deque(maxlen=300))
    error: str | None = None


@dataclass
class Job:
    scan_id: str
    config: ScanConfig
    state: JobState
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)


class JobManager:
    def __init__(self, db: Database, data_dir: Path) -> None:
        self.db = db
        self.data_dir = data_dir
        self.queue: asyncio.Queue[Job] = asyncio.Queue()
        self.jobs: dict[str, Job] = {}
        self.current: Job | None = None
        self._worker: asyncio.Task | None = None
        self._last_phase: dict[str, str] = {}

    async def start(self) -> None:
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._worker_loop(), name="vulnscan-worker")

    async def shutdown(self) -> None:
        if self.current:
            self.current.cancel_event.set()
        if self._worker:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
        self._worker = None

    def enqueue(self, scan_id: str, config: ScanConfig) -> Job:
        state = JobState(scan_id=scan_id)
        job = Job(scan_id=scan_id, config=config, state=state)
        self.jobs[scan_id] = job
        self._log(job, "已排入掃描佇列")
        self.queue.put_nowait(job)
        self.db.update_scan(
            scan_id,
            status="queued",
            phase="排隊中",
            progress=0,
            message="已排入掃描佇列",
        )
        return job

    async def cancel(self, scan_id: str) -> bool:
        job = self.jobs.get(scan_id)
        if not job:
            scan = self.db.get_scan(scan_id)
            if scan and scan.status in ("queued", "running"):
                self.db.update_scan(
                    scan_id,
                    status="cancelled",
                    finished_at=utcnow(),
                    message="掃描已取消",
                    error=None,
                )
                return True
            return False
        if job.state.status in ("completed", "failed", "cancelled"):
            return False
        job.cancel_event.set()
        if job.state.status == "queued":
            job.state.status = "cancelled"
            job.state.message = "掃描已取消"
            job.state.phase = "已取消"
            self.db.update_scan(
                scan_id,
                status="cancelled",
                phase="已取消",
                message="掃描已取消",
                finished_at=utcnow(),
            )
            self._scrub(job)
        else:
            job.state.message = "正在取消…"
            self._log(job, "收到取消要求，正在停止掃描")
        return True

    async def _worker_loop(self) -> None:
        while True:
            job = await self.queue.get()
            try:
                if job.cancel_event.is_set():
                    job.state.status = "cancelled"
                    job.state.phase = "已取消"
                    job.state.message = "掃描已取消"
                    self.db.update_scan(
                        job.scan_id,
                        status="cancelled",
                        phase="已取消",
                        message="掃描已取消",
                        finished_at=utcnow(),
                    )
                    continue
                await self._run_job(job)
            finally:
                self._scrub(job)
                self.queue.task_done()

    async def _run_job(self, job: Job) -> None:
        self.current = job
        job.state.status = "running"
        job.state.phase = "驗證範圍"
        job.state.message = "開始掃描"
        self._log(job, "開始掃描")
        self.db.update_scan(
            job.scan_id,
            status="running",
            started_at=utcnow(),
            phase=job.state.phase,
            progress=1,
            message=job.state.message,
            error=None,
        )
        self._last_phase[job.scan_id] = ""

        def on_update(phase: str, message: str, stats: dict[str, Any], progress: int) -> None:
            job.state.phase_key = phase
            job.state.phase = _phase_label(phase)
            job.state.progress = progress
            job.state.message = message
            job.state.stats = stats
            if message:
                self._log(job, message)
            if self._last_phase.get(job.scan_id) != phase:
                self._last_phase[job.scan_id] = phase
                try:
                    self.db.update_scan(
                        job.scan_id,
                        phase=job.state.phase,
                        progress=progress,
                        message=message,
                    )
                except Exception as exc:  # live state is still in memory
                    self._log(job, f"更新掃描狀態失敗：{exc}")

        engine = ScanEngine(
            scan_id=job.scan_id,
            config=job.config,
            db=self.db,
            data_dir=self.data_dir,
            cancel_event=job.cancel_event,
            on_update=on_update,
        )
        try:
            result = await engine.run()
            job.state.status = "completed"
            job.state.phase = "已完成"
            job.state.progress = 100
            job.state.message = f"掃描完成：{result.stats.findings} 個發現"
            job.state.stats = result.stats.model_dump()
            self._log(job, job.state.message)
            self.db.update_scan(
                job.scan_id,
                status="completed",
                finished_at=utcnow(),
                phase="已完成",
                progress=100,
                message=job.state.message,
                stats_json=json.dumps(result.stats.model_dump(), ensure_ascii=False),
                error=None,
            )
        except ScanCancelled:
            job.state.status = "cancelled"
            job.state.phase = "已取消"
            job.state.message = "掃描已取消，已保留部分結果"
            self._log(job, job.state.message)
            self.db.update_scan(
                job.scan_id,
                status="cancelled",
                finished_at=utcnow(),
                phase="已取消",
                progress=job.state.progress,
                message=job.state.message,
                stats_json=json.dumps(job.state.stats, ensure_ascii=False),
                error=None,
            )
        except Exception as exc:
            job.state.status = "failed"
            job.state.phase = "失敗"
            job.state.error = str(exc)
            job.state.message = f"掃描失敗：{exc}"
            self._log(job, job.state.message)
            self.db.update_scan(
                job.scan_id,
                status="failed",
                finished_at=utcnow(),
                phase="失敗",
                progress=job.state.progress,
                message=job.state.message,
                stats_json=json.dumps(job.state.stats, ensure_ascii=False),
                error=str(exc),
            )
        finally:
            self._scrub(job)
            self.current = None

    @staticmethod
    def _scrub(job: Job) -> None:
        """Drop credentials and large in-memory inputs as soon as the scan is done."""
        job.config = job.config.model_copy(
            update={
                "auth": AuthConfig(),
                "bola_auth": None,
                "proxy": None,
                "openapi_spec": None,
            }
        )

    def status(self, scan_id: str) -> dict[str, Any] | None:
        job = self.jobs.get(scan_id)
        if job:
            state = job.state
            payload = {
                "id": scan_id,
                "status": state.status,
                "phase": state.phase,
                "phase_key": state.phase_key,
                "progress": state.progress,
                "message": state.message,
                "stats": state.stats,
                "logs": list(state.logs)[-80:],
                "error": state.error,
            }
        else:
            scan = self.db.get_scan(scan_id)
            if not scan:
                return None
            try:
                stats = json.loads(scan.stats_json) if scan.stats_json else {}
            except json.JSONDecodeError:
                stats = {}
            payload = {
                "id": scan.id,
                "status": scan.status,
                "phase": scan.phase,
                "phase_key": _phase_key_from_label(scan.phase),
                "progress": scan.progress,
                "message": scan.message,
                "stats": stats,
                "logs": [],
                "error": scan.error,
            }
        payload["recent_findings"] = self._recent_findings(scan_id)
        return payload

    def _recent_findings(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self.db.get_findings(scan_id, limit=12)
        return [
            {
                "id": row.id,
                "title": row.title,
                "severity": row.severity,
                "url": row.url,
                "parameter": row.parameter,
                "confidence": row.confidence,
            }
            for row in rows
        ]

    @staticmethod
    def _log(job: Job, message: str) -> None:
        if not message:
            return
        if job.state.logs and job.state.logs[-1]["message"] == message:
            return
        job.state.logs.append(
            {
                "ts": datetime.now().strftime("%H:%M:%S"),
                "message": message,
            }
        )


def _phase_label(phase: str) -> str:
    return {
        "validate": "驗證範圍",
        "crawl": "探索頁面",
        "passive": "被動檢查",
        "active": "主動檢查",
        "report": "彙整結果",
    }.get(phase, phase)


def _phase_key_from_label(label: str) -> str:
    return {
        "驗證範圍": "validate",
        "探索頁面": "crawl",
        "被動檢查": "passive",
        "主動檢查": "active",
        "彙整結果": "report",
    }.get(label, "")
