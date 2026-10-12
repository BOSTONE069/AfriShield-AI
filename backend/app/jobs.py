"""Bounded in-process background inference workers and job state."""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial

from backend.app.analyzer import analyze_threat
from backend.app.config import get_settings


class AnalysisQueueFullError(RuntimeError):
    """Raised when the bounded inference queue has no capacity."""


@dataclass
class AnalysisJob:
    job_id: str
    owner_id: str
    status: str = "queued"
    submitted_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    result: dict | None = None
    error_code: str | None = None
    touched_at: float = field(default_factory=time.monotonic)

    def public(self) -> dict:
        return {
            "job_id": self.job_id,
            "status": self.status,
            "submitted_at": self.submitted_at,
            "updated_at": self.updated_at,
            "result": self.result,
            "error_code": self.error_code,
        }


class AnalysisJobQueue:
    """Run expensive analysis away from request workers with bounded capacity."""

    def __init__(self) -> None:
        settings = get_settings()
        self._executor = ThreadPoolExecutor(max_workers=settings.analysis_workers, thread_name_prefix="analysis")
        self._capacity = threading.BoundedSemaphore(settings.analysis_workers + settings.analysis_queue_size)
        self._jobs: dict[str, AnalysisJob] = {}
        self._lock = threading.Lock()

    def submit(
        self,
        owner_id: str,
        input_type: str,
        content: str,
        context: str,
        remote_processing_consent: bool,
    ) -> AnalysisJob:
        self._purge_expired()
        if not self._capacity.acquire(blocking=False):
            raise AnalysisQueueFullError("Analysis queue is full")
        job = AnalysisJob(job_id=str(uuid.uuid4()), owner_id=owner_id)
        with self._lock:
            self._jobs[job.job_id] = job
        try:
            future = self._executor.submit(
                self._run,
                job.job_id,
                input_type,
                content,
                context,
                remote_processing_consent,
            )
        except Exception:
            self._capacity.release()
            with self._lock:
                self._jobs.pop(job.job_id, None)
            raise
        future.add_done_callback(partial(self._complete, job.job_id))
        return job

    def get(self, job_id: str) -> AnalysisJob | None:
        self._purge_expired()
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.touched_at = time.monotonic()
            return job

    def _run(
        self,
        job_id: str,
        input_type: str,
        content: str,
        context: str,
        remote_processing_consent: bool,
    ) -> dict:
        self._update(job_id, status="running")
        return analyze_threat(input_type, content, context, remote_processing_consent=remote_processing_consent)

    def _complete(self, job_id: str, future: Future[dict]) -> None:
        try:
            result = future.result()
            self._update(job_id, status="completed", result=result)
        except Exception:
            self._update(job_id, status="failed", error_code="analysis_failed")
        finally:
            self._capacity.release()

    def _update(self, job_id: str, **changes: object) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in changes.items():
                setattr(job, key, value)
            job.updated_at = datetime.now(UTC).isoformat()
            job.touched_at = time.monotonic()

    def _purge_expired(self) -> None:
        cutoff = time.monotonic() - get_settings().analysis_job_retention_seconds
        with self._lock:
            expired = [job_id for job_id, job in self._jobs.items() if job.touched_at < cutoff]
            for job_id in expired:
                del self._jobs[job_id]


_QUEUE: AnalysisJobQueue | None = None
_QUEUE_LOCK = threading.Lock()


def get_job_queue() -> AnalysisJobQueue:
    global _QUEUE
    with _QUEUE_LOCK:
        if _QUEUE is None:
            _QUEUE = AnalysisJobQueue()
        return _QUEUE
