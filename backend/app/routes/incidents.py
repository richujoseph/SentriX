from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..db import get_db
from ..llm import LLMError
from ..llm.summarizer import summarize_incident
from ..models import Incident, RawAlert, incident_alerts
from .alerts import AlertOut

router = APIRouter(prefix="/incidents", tags=["incidents"])


class MitreTacticOut(BaseModel):
    id: str
    name: str
    first_seen: datetime
    alert_ids: list[int]


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    src_ip: str
    start_time: datetime
    end_time: datetime | None
    severity_score: float
    mitre_tactics: list[MitreTacticOut]
    summary: str | None
    recommended_action: str | None
    status: str
    alert_count: int


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut]


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int
    limit: int
    offset: int


def to_out(incident: Incident, alert_count: int, **extra: Any) -> dict[str, Any]:
    data = IncidentOut.model_validate({**incident.__dict__, "alert_count": alert_count}).model_dump()
    return {**data, **extra}


@router.get("", response_model=IncidentPage)
def list_incidents(
    status: str | None = Query(None, description="Filter by status, e.g. open"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> IncidentPage:
    """Incidents, most severe first."""
    alert_count = (
        select(func.count())
        .select_from(incident_alerts)
        .where(incident_alerts.c.incident_id == Incident.id)
        .scalar_subquery()
    )
    query = select(Incident, alert_count)
    total_query = select(func.count()).select_from(Incident)
    if status is not None:
        query = query.where(Incident.status == status)
        total_query = total_query.where(Incident.status == status)

    rows = db.execute(
        query.order_by(Incident.severity_score.desc(), Incident.start_time.desc(), Incident.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return IncidentPage(
        items=[to_out(incident, count) for incident, count in rows],
        total=db.scalar(total_query),
        limit=limit,
        offset=offset,
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """One incident with its member alerts in time order."""
    incident = db.scalars(
        select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.alerts))
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = sorted(incident.alerts, key=lambda a: (a.timestamp, a.id))
    return to_out(incident, len(alerts), alerts=[AlertOut.model_validate(a) for a in alerts])


@router.post("/{incident_id}/summarize", response_model=IncidentOut)
def summarize(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Generate the incident's summary and recommended action with the configured LLM.

    Blocks until the model answers (can take tens of seconds with a local model).
    Returns 502 if the LLM is unavailable or doesn't follow the output format.
    """
    incident = db.scalars(
        select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.alerts))
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        summarize_incident(db, incident)
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=f"Summarization failed: {exc}") from exc
    return to_out(incident, len(incident.alerts))
