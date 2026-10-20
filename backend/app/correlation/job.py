"""Background job: correlate un-correlated alerts into incidents.

Every ``CORRELATION_INTERVAL_SECONDS`` the job loads alerts that belong to no
incident, groups them with the engine, and writes ``incidents`` and
``incident_alerts`` rows. New alerts that continue an existing open incident
(same source, within the window of it) are added to that incident and it is
rescored and retagged, so a slow attack isn't split across job runs.

After each correlation pass, incidents scoring at least ``SUMMARIZE_THRESHOLD``
that have no summary are summarised by the LLM. If the LLM fails, a template
fallback summary is stored instead and retried later; while the LLM is
unreachable, calls pause for ``SUMMARIZE_RETRY_SECONDS`` so a dead or hung
backend can't stall the loop.
"""

import asyncio
import logging
import os
from dataclasses import asdict
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..llm import LLMBackend, LLMError, get_llm_backend
from ..llm.summarizer import (
    FALLBACK_PREFIX,
    SummaryParseError,
    apply_fallback_summary,
    is_fallback_summary,
    summarize_incident,
)
from ..models import Asset, Incident, RawAlert, incident_alerts
from .engine import IncidentCandidate, MitreTactic, group_alerts, score_incident, tag_mitre

log = logging.getLogger(__name__)

CORRELATION_WINDOW_MINUTES = float(os.environ.get("CORRELATION_WINDOW_MINUTES", "10"))
CORRELATION_INTERVAL_SECONDS = float(os.environ.get("CORRELATION_INTERVAL_SECONDS", "30"))
SUMMARIZE_THRESHOLD = float(os.environ.get("SUMMARIZE_THRESHOLD", "50"))
SUMMARIZE_BATCH = int(os.environ.get("SUMMARIZE_BATCH", "3"))
SUMMARIZE_RETRY_SECONDS = float(os.environ.get("SUMMARIZE_RETRY_SECONDS", "300"))

# Monotonic times before which LLM calls are skipped: globally while the
# backend is down, and per incident after its answer couldn't be parsed.
_llm_paused_until = 0.0
_incident_retry_after: dict[int, float] = {}


def tactics_to_json(tactics: list[MitreTactic]) -> list[dict[str, Any]]:
    return [{**asdict(t), "first_seen": t.first_seen.isoformat()} for t in tactics]


def find_open_incident(db: Session, candidate: IncidentCandidate, window: timedelta) -> Incident | None:
    """The open incident from the same source that the candidate continues, if any."""
    return db.scalars(
        select(Incident)
        .where(
            Incident.src_ip == candidate.src_ip,
            Incident.status == "open",
            Incident.end_time >= candidate.start_time - window,
            Incident.start_time <= candidate.end_time + window,
        )
        .order_by(Incident.end_time.desc())
        .limit(1)
    ).first()


def apply_candidate(incident: Incident, candidate: IncidentCandidate, assets: list[Asset]) -> None:
    """Score and tag the candidate and copy the results onto the incident row."""
    incident.start_time = candidate.start_time
    incident.end_time = candidate.end_time
    incident.severity_score = score_incident(candidate, assets)
    incident.mitre_tactics = tactics_to_json(tag_mitre(candidate))


def correlate_once(window_minutes: float = CORRELATION_WINDOW_MINUTES) -> tuple[int, int]:
    """Run one correlation pass. Returns (incidents created, incidents extended)."""
    window = timedelta(minutes=window_minutes)
    created = extended = 0

    with SessionLocal() as db:
        uncorrelated = db.scalars(
            select(RawAlert).where(~exists().where(incident_alerts.c.alert_id == RawAlert.id))
        ).all()
        if not uncorrelated:
            return 0, 0
        assets = list(db.scalars(select(Asset)))

        for candidate in group_alerts(uncorrelated, window_minutes):
            incident = find_open_incident(db, candidate, window)
            if incident is None:
                incident = Incident(src_ip=candidate.src_ip, status="open")
                db.add(incident)
                created += 1
            else:
                # Rescore over the incident's existing alerts plus the new ones.
                members = sorted(incident.alerts + candidate.alerts, key=lambda a: (a.timestamp, a.id))
                candidate = IncidentCandidate(
                    src_ip=candidate.src_ip,
                    start_time=members[0].timestamp,
                    end_time=members[-1].timestamp,
                    alert_ids=[a.id for a in members],
                    alerts=members,
                )
                # The incident changed, so any existing summary is now stale.
                incident.summary = None
                incident.recommended_action = None
                extended += 1

            new_alerts = [a for a in candidate.alerts if a not in incident.alerts]
            incident.alerts.extend(new_alerts)
            apply_candidate(incident, candidate, assets)
            db.flush()  # so a later candidate in this pass can find and extend it

        db.commit()
    return created, extended


def summarize_pending(
    threshold: float = SUMMARIZE_THRESHOLD,
    backend: LLMBackend | None = None,
) -> tuple[int, int]:
    """Summarise high-severity incidents that lack a summary (or only have a fallback).

    Handles at most ``SUMMARIZE_BATCH`` incidents per call, most severe first.
    Never raises on LLM failure: the incident gets a fallback summary instead.

    Returns:
        (incidents summarised by the LLM, incidents given a fallback summary).
    """
    global _llm_paused_until
    now = time.monotonic()
    summarized = fell_back = 0

    with SessionLocal() as db:
        pending = db.scalars(
            select(Incident)
            .where(
                Incident.severity_score >= threshold,
                or_(Incident.summary.is_(None), Incident.summary.startswith(FALLBACK_PREFIX)),
            )
            .order_by(Incident.severity_score.desc(), Incident.id)
        ).all()
        pending = [i for i in pending if _incident_retry_after.get(i.id, 0.0) <= now][:SUMMARIZE_BATCH]
        if not pending:
            return 0, 0

        try:
            backend = backend or get_llm_backend()
        except ValueError as exc:  # misconfigured LLM_BACKEND
            log.error("Auto-summary disabled: %s", exc)
            backend = None

        for incident in pending:
            llm_available = backend is not None and _llm_paused_until <= now
            if llm_available:
                try:
                    summarize_incident(db, incident, backend)
                    _incident_retry_after.pop(incident.id, None)
                    summarized += 1
                    continue
                except SummaryParseError as exc:
                    # The model answered but ignored the format; retry this one later.
                    db.rollback()
                    log.warning("Incident %d: unusable LLM answer, using fallback: %s", incident.id, exc)
                    _incident_retry_after[incident.id] = now + SUMMARIZE_RETRY_SECONDS
                except LLMError as exc:
                    db.rollback()
                    log.warning(
                        "LLM unavailable, using fallback summaries for %ds: %s", SUMMARIZE_RETRY_SECONDS, exc
                    )
                    _llm_paused_until = now + SUMMARIZE_RETRY_SECONDS

            # LLM failed or is paused: make sure the incident has at least a fallback.
            if incident.summary is None:
                apply_fallback_summary(db, incident)
                fell_back += 1
            elif is_fallback_summary(incident.summary):
                # Refresh it in case the incident's details changed.
                apply_fallback_summary(db, incident)

    return summarized, fell_back


async def run_correlation_loop() -> None:
    """Run ``correlate_once`` every CORRELATION_INTERVAL_SECONDS until cancelled."""
    log.info(
        "Correlating alerts every %ss with a %s-minute window; auto-summarizing incidents scoring >= %s",
        CORRELATION_INTERVAL_SECONDS,
        CORRELATION_WINDOW_MINUTES,
        SUMMARIZE_THRESHOLD,
    )
    while True:
        try:
            created, extended = await asyncio.to_thread(correlate_once)
            if created or extended:
                log.info("Correlation: %d incident(s) created, %d extended", created, extended)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Correlation pass failed")

        # Runs after correlation in the same loop, so it never races an incident
        # being extended (which clears its summary).
        try:
            summarized, fell_back = await asyncio.to_thread(summarize_pending)
            if summarized or fell_back:
                log.info("Auto-summary: %d summarized, %d fallback", summarized, fell_back)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Auto-summary pass failed")

        await asyncio.sleep(CORRELATION_INTERVAL_SECONDS)
