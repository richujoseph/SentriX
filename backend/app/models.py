from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
    Column("alert_id", ForeignKey("raw_alerts.id", ondelete="CASCADE"), primary_key=True),
)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("criticality BETWEEN 1 AND 5", name="ck_assets_criticality"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac: Mapped[str | None] = mapped_column(String(17))
    role: Mapped[str | None] = mapped_column(String(64))
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RawAlert(Base):
    __tablename__ = "raw_alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dest_port: Mapped[int | None] = mapped_column(Integer)
    signature: Mapped[str] = mapped_column(String(512))
    category: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    # Stable hash of the alert's identity, so re-ingesting the same event is a no-op.
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)

    incidents: Mapped[list["Incident"]] = relationship(
        secondary=incident_alerts, back_populates="alerts"
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    severity_score: Mapped[float] = mapped_column(Float, default=0.0)
    mitre_tactics: Mapped[list[str]] = mapped_column(JSON, default=list)
    summary: Mapped[str | None] = mapped_column(Text)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)

    alerts: Mapped[list[RawAlert]] = relationship(
        secondary=incident_alerts, back_populates="incidents"
    )


class IngestState(Base):
    """Read position of a tailed log file, so restarts resume instead of re-ingesting."""

    __tablename__ = "ingest_state"

    path: Mapped[str] = mapped_column(String(1024), primary_key=True)
    inode: Mapped[int] = mapped_column(BigInteger)
    offset: Mapped[int] = mapped_column(BigInteger, default=0)
