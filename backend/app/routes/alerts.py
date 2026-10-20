from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
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


@router.post("", response_model=AlertOut, status_code=status.HTTP_201_CREATED)
def create_alert(alert: AlertIn, db: Session = Depends(get_db)) -> RawAlert:
    row = RawAlert(**alert.model_dump())
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


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
