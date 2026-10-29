import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import (
    Boolean,
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    Index,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

load_dotenv()
Path("data").mkdir(exist_ok=True)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/cybertwin.db")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {},
)
SessionLocal = sessionmaker(engine, expire_on_commit=False)


@event.listens_for(Engine, "connect")
def sqlite_constraints(connection, record):
    if isinstance(connection, sqlite3.Connection):
        connection.execute("PRAGMA foreign_keys=ON")


def now():
    return datetime.now(timezone.utc)


def aware(t):
    return t.replace(tzinfo=timezone.utc) if t.tzinfo is None else t


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="admin")


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    expires: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index(
            "ix_events_correlation", "src_ip", "origin", "detection_source", "timestamp"
        ),
        CheckConstraint("risk BETWEEN 0 AND 100", name="ck_event_risk"),
        CheckConstraint(
            "origin IN ('simulation','replay','live')", name="ck_event_origin"
        ),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None]
    dst_port: Mapped[int | None]
    protocol: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(100))
    origin: Mapped[str] = mapped_column(String(20), index=True)
    detection_source: Mapped[str] = mapped_column(String(60))
    rule: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    risk: Mapped[int]
    ml_score: Mapped[float | None]
    confidence: Mapped[float | None]
    evidence: Mapped[list] = mapped_column(JSON)
    features: Mapped[dict] = mapped_column(JSON)
    action: Mapped[str] = mapped_column(String(100), default="observed")
    status: Mapped[str] = mapped_column(String(30), default="open")
    flow_id: Mapped[str | None] = mapped_column(
        ForeignKey("network_flows.id"), index=True
    )
    record_key: Mapped[str | None] = mapped_column(String(64), unique=True)
    observation: Mapped[dict | None] = mapped_column(JSON)
    detection: Mapped[dict | None] = mapped_column(JSON)


class Flow(Base):
    __tablename__ = "network_flows"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    origin: Mapped[str] = mapped_column(String(20), index=True)
    sensor: Mapped[str] = mapped_column(String(80), index=True)
    sensor_flow_id: Mapped[str | None] = mapped_column(String(100))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int | None]
    dst_port: Mapped[int | None]
    ip_version: Mapped[int]
    protocol: Mapped[str] = mapped_column(String(20), index=True)
    app_protocol: Mapped[str | None] = mapped_column(String(80))
    packets: Mapped[int | None] = mapped_column(BigInteger)
    bytes_src: Mapped[int | None] = mapped_column(BigInteger)
    bytes_dst: Mapped[int | None] = mapped_column(BigInteger)
    total_bytes: Mapped[int | None] = mapped_column(BigInteger)
    duration: Mapped[float | None]
    state: Mapped[str | None] = mapped_column(String(40))
    tcp_flags: Mapped[str | None] = mapped_column(String(80))
    availability: Mapped[dict] = mapped_column(JSON)
    limitations: Mapped[list] = mapped_column(JSON)
    risk: Mapped[int] = mapped_column(default=0)


class PreventionDecision(Base):
    __tablename__ = "prevention_decisions"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), index=True)
    flow_id: Mapped[str | None] = mapped_column(
        ForeignKey("network_flows.id"), index=True
    )
    block_id: Mapped[int | None] = mapped_column(ForeignKey("blocks.id"), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    policy: Mapped[str] = mapped_column(String(30))
    outcome: Mapped[str] = mapped_column(String(50))
    steps: Mapped[list] = mapped_column(JSON)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint("criticality BETWEEN 1 AND 5", name="ck_device_criticality"),
        CheckConstraint(
            "vulnerability BETWEEN 0 AND 10", name="ck_device_vulnerability"
        ),
    )
    id: Mapped[str] = mapped_column(String(60), primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(50))
    ip: Mapped[str] = mapped_column(String(45), unique=True)
    criticality: Mapped[int]
    vulnerability: Mapped[int]
    x: Mapped[float] = mapped_column(Float, default=0)
    y: Mapped[float] = mapped_column(Float, default=0)
    segment: Mapped[str | None] = mapped_column(String(80))


class Connection(Base):
    __tablename__ = "connections"
    __table_args__ = (
        UniqueConstraint("source", "target", name="uq_connection_pair"),
        CheckConstraint("source <> target", name="ck_connection_distinct"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    target: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)


class AccessRule(Base):
    __tablename__ = "access_rules"
    connection_id: Mapped[int] = mapped_column(
        ForeignKey("connections.id"), primary_key=True
    )
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_ports: Mapped[list | None] = mapped_column(JSON)
    protocol: Mapped[str | None] = mapped_column(String(20))


class Block(Base):
    __tablename__ = "blocks"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    reason: Mapped[str] = mapped_column(Text)
    created: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    state: Mapped[str] = mapped_column(String(30), default="active", index=True)
    adapter: Mapped[str] = mapped_column(String(30))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)


class Audit(Base):
    __tablename__ = "enforcement_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(100))
    detail: Mapped[dict] = mapped_column(JSON)


class Note(Base):
    __tablename__ = "investigation_notes"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    text: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(80))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Scenario(Base):
    __tablename__ = "scenarios"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    name: Mapped[str] = mapped_column(String(100))
    data: Mapped[dict] = mapped_column(JSON)


class ModelMetadata(Base):
    __tablename__ = "model_metadata"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    metrics: Mapped[dict] = mapped_column(JSON)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


def audit(db, actor, action, **detail):
    db.add(Audit(actor=actor, action=action, detail=detail))


def config(db):
    row = db.get(Setting, "enforcement")
    return (
        row.value
        if row
        else {"mode": "detection", "threshold": 85, "duration_minutes": 30}
    )
