import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import RawAlert

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertIn(BaseModel):
    src_ip: str = Field(max_length=45)
    dest_ip: str | None = Field(default=None, max_length=45)
    dest_port: int | None = Field(default=None, ge=0, le=65535)
    signature: str = Field(max_length=512)
    category: str | None = Field(default=None, max_length=255)
    severity: int | None = None
    timestamp: datetime
    raw_json: dict[str, Any]


class AlertOut(AlertIn):
    model_config = ConfigDict(from_attributes=True)

    id: int


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int


def alert_fingerprint(
    timestamp: datetime,
    src_ip: str,
    dest_ip: str | None,
    dest_port: int | None,
    signature: str,
    raw_json: dict[str, Any],
) -> str:
    """Hash the fields that identify an alert event.

    Suricata's flow_id and pcap_cnt are deliberately excluded: they change every
    time the same capture is reprocessed.
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    rule = raw_json.get("alert", {})
    key = [
        timestamp.astimezone(timezone.utc).isoformat(),
        src_ip,
        raw_json.get("src_port"),
        dest_ip,
        dest_port,
        raw_json.get("proto"),
        rule.get("gid"),
        rule.get("signature_id"),
        rule.get("rev"),
        signature,
    ]
    return hashlib.sha256(json.dumps(key).encode()).hexdigest()


@router.post(
    "",
    response_model=AlertOut,
    status_code=status.HTTP_201_CREATED,
    responses={200: {"description": "Alert already stored; existing record returned"}},
)
def create_alert(alert: AlertIn, response: Response, db: Session = Depends(get_db)) -> RawAlert:
    data = alert.model_dump()
    fingerprint = alert_fingerprint(
        alert.timestamp, alert.src_ip, alert.dest_ip, alert.dest_port, alert.signature, alert.raw_json
    )
    new_id = db.scalar(
        insert(RawAlert)
        .values(**data, fingerprint=fingerprint)
        .on_conflict_do_nothing(index_elements=[RawAlert.fingerprint])
        .returning(RawAlert.id)
    )
    db.commit()
    if new_id is None:
        response.status_code = status.HTTP_200_OK
        return db.scalars(select(RawAlert).where(RawAlert.fingerprint == fingerprint)).one()
    return db.get(RawAlert, new_id)


@router.get("", response_model=AlertPage)
def list_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> AlertPage:
    total = db.scalar(select(func.count()).select_from(RawAlert))
    rows = db.scalars(
        select(RawAlert)
        .order_by(RawAlert.timestamp.desc(), RawAlert.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return AlertPage(items=rows, total=total, limit=limit, offset=offset)
