"""Background job: correlate un-correlated alerts into incidents.

Every ``CORRELATION_INTERVAL_SECONDS`` the job loads alerts that belong to no
incident, groups them with the engine, and writes ``incidents`` and
``incident_alerts`` rows. New alerts that continue an existing open incident
(same source, within the window of it) are added to that incident and it is
rescored and retagged, so a slow attack isn't split across job runs.
"""

import asyncio
import logging
import os
from dataclasses import asdict
from datetime import timedelta
from typing import Any

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Asset, Incident, RawAlert, incident_alerts
from .engine import IncidentCandidate, MitreTactic, group_alerts, score_incident, tag_mitre

log = logging.getLogger(__name__)

CORRELATION_WINDOW_MINUTES = float(os.environ.get("CORRELATION_WINDOW_MINUTES", "10"))
CORRELATION_INTERVAL_SECONDS = float(os.environ.get("CORRELATION_INTERVAL_SECONDS", "30"))


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


async def run_correlation_loop() -> None:
    """Run ``correlate_once`` every CORRELATION_INTERVAL_SECONDS until cancelled."""
    log.info(
        "Correlating alerts every %ss with a %s-minute window",
        CORRELATION_INTERVAL_SECONDS,
        CORRELATION_WINDOW_MINUTES,
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
        await asyncio.sleep(CORRELATION_INTERVAL_SECONDS)
