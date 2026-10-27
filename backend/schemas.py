from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator


class Features(BaseModel):
    duration: float = Field(0, ge=0, le=86400)
    packets: int = Field(0, ge=0, le=100000000)
    bytes: int = Field(0, ge=0, le=100000000000)
    frequency: int = Field(1, ge=0, le=1000000)
    failed_auth: int = Field(0, ge=0, le=1000000)
    criticality: int = Field(1, ge=1, le=5)


class EventInput(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int | None = Field(None, ge=0, le=65535)
    dst_port: int | None = Field(None, ge=0, le=65535)
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] = "TCP"
    category: str = Field("connection", max_length=100)
    features: Features = Field(default_factory=Features)
    signature: str | None = Field(None, max_length=500)
    signature_severity: int = Field(3, ge=1, le=3)

    @field_validator("timestamp")
    @classmethod
    def utc(cls, value):
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class BlockInput(BaseModel):
    ip: IPvAnyAddress
    reason: str = Field(min_length=5, max_length=500)
    minutes: int = Field(30, ge=1, le=1440)
    confirmed: bool = False


class EnforcementConfig(BaseModel):
    mode: Literal["detection", "manual", "automatic"] = "detection"
    threshold: int = Field(85, ge=70, le=100)
    duration_minutes: int = Field(30, ge=1, le=1440)
    confirmed: bool = False


class DeviceInput(BaseModel):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,60}$")
    name: str = Field(min_length=1, max_length=80)
    kind: str = Field(min_length=1, max_length=50)
    ip: IPvAnyAddress
    criticality: int = Field(1, ge=1, le=5)
    vulnerability: int = Field(0, ge=0, le=10)
    x: float = Field(0, ge=-10000, le=10000)
    y: float = Field(0, ge=-10000, le=10000)


class ConnectionInput(BaseModel):
    source: str = Field(max_length=60)
    target: str = Field(max_length=60)
    allowed: bool = True


class SimulationInput(BaseModel):
    name: str = Field("Defense comparison", max_length=100)
    initial: str = Field("web", max_length=60)
    blocked_connections: list[int] = Field(default_factory=list, max_length=200)
    patched: list[str] = Field(default_factory=list, max_length=100)
    isolated: list[str] = Field(default_factory=list, max_length=100)
