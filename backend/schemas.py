from datetime import datetime, timezone
from typing import Literal, Annotated
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator, model_validator


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
    sensor: str | None = Field(None, max_length=80)
    sensor_flow_id: str | None = Field(None, max_length=100)
    app_protocol: str | None = Field(None, max_length=80)
    bytes_src: int | None = Field(None, ge=0, le=100000000000)
    bytes_dst: int | None = Field(None, ge=0, le=100000000000)
    connection_state: str | None = Field(None, max_length=40)
    tcp_flags: str | None = Field(None, max_length=80)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_record: dict | None = None
    limitations: list[str] = Field(default_factory=list, max_length=30)

    @model_validator(mode="after")
    def coherent_observation(self):
        if self.src_ip.version != self.dst_ip.version:
            raise ValueError(
                "An IP observation must use the same IP version at both endpoints"
            )
        if (self.first_seen or self.timestamp) > (self.last_seen or self.timestamp):
            raise ValueError("first_seen must not be after last_seen")
        return self

    @field_validator("timestamp", "first_seen", "last_seen")
    @classmethod
    def utc(cls, value):
        if value is None:
            return None
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
    event_id: int | None = Field(None, ge=1)


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
    segment: str | None = Field(None, max_length=80)


class ConnectionInput(BaseModel):
    source: str = Field(max_length=60)
    target: str = Field(max_length=60)
    allowed: bool = True
    allowed_ports: list[Annotated[int, Field(ge=0, le=65535)]] | None = Field(
        None, max_length=100
    )
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None


class SimulationInput(BaseModel):
    name: str = Field("Defense comparison", max_length=100)
    initial: str = Field("web", max_length=60)
    blocked_connections: list[int] = Field(default_factory=list, max_length=200)
    patched: list[str] = Field(default_factory=list, max_length=100)
    isolated: list[str] = Field(default_factory=list, max_length=100)
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"] | None = None
    dst_port: int | None = Field(None, ge=0, le=65535)
