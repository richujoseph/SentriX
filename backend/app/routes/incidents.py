from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..db import get_db
from ..llm import LLMError
from ..llm.summarizer import summarize_incident
from ..models import Asset, Incident, RawAlert, incident_alerts
from ..reports.pdf import render_incident_pdf
from .alerts import AlertOut

router = APIRouter(prefix="/incidents", tags=["incidents"])


class MitreTacticOut(BaseModel):
    id: str
    name: str
    first_seen: datetime
    alert_ids: list[int]


class TargetOut(BaseModel):
    ip: str
    known_asset: bool
    hostname: str | None = None
    role: str | None = None
    criticality: int | None = None
    mac: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None


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
    # Hosts the incident's alerts were aimed at, most critical first.
    targets: list[TargetOut] = []


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut]


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int
    limit: int
    offset: int


def load_targets(db: Session, incident_ids: list[int]) -> dict[int, list[TargetOut]]:
    """Distinct destination IPs per incident, enriched from the asset inventory."""
    if not incident_ids:
        return {}
    pairs = db.execute(
        select(incident_alerts.c.incident_id, RawAlert.dest_ip)
        .join(RawAlert, RawAlert.id == incident_alerts.c.alert_id)
        .where(incident_alerts.c.incident_id.in_(incident_ids), RawAlert.dest_ip.is_not(None))
        .distinct()
    ).all()
    ips = {ip for _, ip in pairs}
    assets = {a.ip: a for a in db.scalars(select(Asset).where(Asset.ip.in_(ips)))} if ips else {}

    targets: dict[int, list[TargetOut]] = {i: [] for i in incident_ids}
    for incident_id, ip in pairs:
        asset = assets.get(ip)
        targets[incident_id].append(
            TargetOut(ip=ip, known_asset=False)
            if asset is None
            else TargetOut(
                ip=ip,
                known_asset=True,
                hostname=asset.hostname,
                role=asset.role,
                criticality=asset.criticality,
                mac=asset.mac,
                first_seen=asset.first_seen,
                last_seen=asset.last_seen,
            )
        )
    for items in targets.values():
        items.sort(key=lambda t: (-(t.criticality or 0), t.ip))
    return targets


def to_out(incident: Incident, alert_count: int, targets: list[TargetOut], **extra: Any) -> dict[str, Any]:
    data = IncidentOut.model_validate(
        {**incident.__dict__, "alert_count": alert_count, "targets": targets}
    ).model_dump()
    return {**data, **extra}


@router.get("", response_model=IncidentPage)
def list_incidents(
    status: str | None = Query(None, description="Filter by status, e.g. open"),
    min_severity: float | None = Query(None, ge=0, le=100, description="Only scores >= this"),
    max_severity: float | None = Query(None, ge=0, le=100, description="Only scores < this"),
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
    filters = []
    if status is not None:
        filters.append(Incident.status == status)
    if min_severity is not None:
        filters.append(Incident.severity_score >= min_severity)
    if max_severity is not None:
        filters.append(Incident.severity_score < max_severity)
    query = query.where(*filters)
    total_query = total_query.where(*filters)

    rows = db.execute(
        query.order_by(Incident.severity_score.desc(), Incident.start_time.desc(), Incident.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    targets = load_targets(db, [incident.id for incident, _ in rows])
    return IncidentPage(
        items=[to_out(incident, count, targets[incident.id]) for incident, count in rows],
        total=db.scalar(total_query),
        limit=limit,
        offset=offset,
    )


def incident_detail(db: Session, incident_id: int) -> dict[str, Any]:
    """An incident with targets and its member alerts in time order; 404 if missing."""
    incident = db.scalars(
        select(Incident).where(Incident.id == incident_id).options(selectinload(Incident.alerts))
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = sorted(incident.alerts, key=lambda a: (a.timestamp, a.id))
    return to_out(
        incident,
        len(alerts),
        load_targets(db, [incident.id])[incident.id],
        alerts=[AlertOut.model_validate(a).model_dump() for a in alerts],
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """One incident with its member alerts in time order."""
    return incident_detail(db, incident_id)


@router.get(
    "/{incident_id}/report.pdf",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}, "description": "Incident report as PDF"}},
)
def incident_report(incident_id: int, db: Session = Depends(get_db)) -> Response:
    """Download the incident as a PDF report (narrative, action, timeline, assets)."""
    pdf = render_incident_pdf(incident_detail(db, incident_id))
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentrix-incident-{incident_id}.pdf"'},
    )


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
    return to_out(incident, len(incident.alerts), load_targets(db, [incident.id])[incident.id])
