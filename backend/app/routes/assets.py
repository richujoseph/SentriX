from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..assets.scanner import ScanError, scan_subnet
from ..db import get_db
from ..models import Asset

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip: str
    hostname: str | None
    mac: str | None
    role: str | None
    criticality: int
    first_seen: datetime
    last_seen: datetime


class AssetPage(BaseModel):
    items: list[AssetOut]
    total: int
    limit: int
    offset: int


class ScanRequest(BaseModel):
    subnet: str | None = None


class OpenPortOut(BaseModel):
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None


class ScannedHostOut(BaseModel):
    ip: str
    hostname: str | None
    mac: str | None
    role: str
    criticality: int
    open_ports: list[OpenPortOut]


class ScanResult(BaseModel):
    subnet: str
    hosts_found: int
    hosts: list[ScannedHostOut]


@router.post("/scan", response_model=ScanResult)
def trigger_scan(request: ScanRequest | None = None, db: Session = Depends(get_db)) -> ScanResult:
    """Run an nmap scan (blocking) and upsert discovered hosts.

    Uses `subnet` from the body, falling back to the SCAN_SUBNET env var.
    """
    try:
        subnet, hosts = scan_subnet(db, request.subnet if request else None)
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ScanResult(subnet=subnet, hosts_found=len(hosts), hosts=[h.to_dict() for h in hosts])


@router.get("", response_model=AssetPage)
def list_assets(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> AssetPage:
    total = db.scalar(select(func.count()).select_from(Asset))
    rows = db.scalars(
        select(Asset).order_by(Asset.criticality.desc(), Asset.ip).limit(limit).offset(offset)
    ).all()
    return AssetPage(items=rows, total=total, limit=limit, offset=offset)
