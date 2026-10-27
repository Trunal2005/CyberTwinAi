import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
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
