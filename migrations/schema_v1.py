# Frozen schema for migration 0001. Do not edit after applying.
from sqlalchemy import *

metadata = MetaData()
Table(
    "blocks",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column("ip", String(length=45), primary_key=False, nullable=False, unique=False),
    Column("reason", Text(), primary_key=False, nullable=False, unique=False),
    Column(
        "created",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column(
        "expires",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column("state", String(length=30), primary_key=False, nullable=False, unique=False),
    Column(
        "adapter", String(length=30), primary_key=False, nullable=False, unique=False
    ),
    Column("verified", Boolean(), primary_key=False, nullable=False, unique=False),
)
Table(
    "devices",
    metadata,
    Column("id", String(length=60), primary_key=True, nullable=False, unique=False),
    Column("name", String(length=80), primary_key=False, nullable=False, unique=False),
    Column("kind", String(length=50), primary_key=False, nullable=False, unique=False),
    Column("ip", String(length=45), primary_key=False, nullable=False, unique=True),
    Column("criticality", Integer(), primary_key=False, nullable=False, unique=False),
    Column("vulnerability", Integer(), primary_key=False, nullable=False, unique=False),
    Column("x", Float(), primary_key=False, nullable=False, unique=False),
    Column("y", Float(), primary_key=False, nullable=False, unique=False),
)
Table(
    "enforcement_logs",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column(
        "timestamp",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column("actor", String(length=80), primary_key=False, nullable=False, unique=False),
    Column(
        "action", String(length=100), primary_key=False, nullable=False, unique=False
    ),
    Column("detail", JSON(), primary_key=False, nullable=False, unique=False),
)
Table(
    "events",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column(
        "timestamp",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column(
        "src_ip", String(length=45), primary_key=False, nullable=False, unique=False
    ),
    Column(
        "dst_ip", String(length=45), primary_key=False, nullable=False, unique=False
    ),
    Column("src_port", Integer(), primary_key=False, nullable=True, unique=False),
    Column("dst_port", Integer(), primary_key=False, nullable=True, unique=False),
    Column(
        "protocol", String(length=20), primary_key=False, nullable=False, unique=False
    ),
    Column(
        "category", String(length=100), primary_key=False, nullable=False, unique=False
    ),
    Column(
        "origin", String(length=20), primary_key=False, nullable=False, unique=False
    ),
    Column(
        "detection_source",
        String(length=60),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column("rule", Text(), primary_key=False, nullable=False, unique=False),
    Column(
        "severity", String(length=20), primary_key=False, nullable=False, unique=False
    ),
    Column("risk", Integer(), primary_key=False, nullable=False, unique=False),
    Column("ml_score", Float(), primary_key=False, nullable=True, unique=False),
    Column("confidence", Float(), primary_key=False, nullable=True, unique=False),
    Column("evidence", JSON(), primary_key=False, nullable=False, unique=False),
    Column("features", JSON(), primary_key=False, nullable=False, unique=False),
    Column(
        "action", String(length=100), primary_key=False, nullable=False, unique=False
    ),
    Column(
        "status", String(length=30), primary_key=False, nullable=False, unique=False
    ),
)
Table(
    "investigation_notes",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column("ip", String(length=45), primary_key=False, nullable=False, unique=False),
    Column("text", Text(), primary_key=False, nullable=False, unique=False),
    Column(
        "author", String(length=80), primary_key=False, nullable=False, unique=False
    ),
    Column(
        "timestamp",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
)
Table(
    "model_metadata",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column(
        "timestamp",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column("metrics", JSON(), primary_key=False, nullable=False, unique=False),
)
Table(
    "scenarios",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column(
        "timestamp",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column("name", String(length=100), primary_key=False, nullable=False, unique=False),
    Column("data", JSON(), primary_key=False, nullable=False, unique=False),
)
Table(
    "settings",
    metadata,
    Column("key", String(length=80), primary_key=True, nullable=False, unique=False),
    Column("value", JSON(), primary_key=False, nullable=False, unique=False),
)
Table(
    "users",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column(
        "username", String(length=80), primary_key=False, nullable=False, unique=True
    ),
    Column("password_hash", Text(), primary_key=False, nullable=False, unique=False),
    Column("role", String(length=20), primary_key=False, nullable=False, unique=False),
)
Table(
    "connections",
    metadata,
    Column("id", Integer(), primary_key=True, nullable=False, unique=False),
    Column(
        "source",
        String(length=60),
        ForeignKey("devices.id"),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column(
        "target",
        String(length=60),
        ForeignKey("devices.id"),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
)
Table(
    "sessions",
    metadata,
    Column(
        "token_hash", String(length=64), primary_key=True, nullable=False, unique=False
    ),
    Column(
        "user_id",
        Integer(),
        ForeignKey("users.id"),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
    Column(
        "expires",
        DateTime(timezone=True),
        primary_key=False,
        nullable=False,
        unique=False,
    ),
)
Table(
    "access_rules",
    metadata,
    Column(
        "connection_id",
        Integer(),
        ForeignKey("connections.id"),
        primary_key=True,
        nullable=False,
        unique=False,
    ),
    Column("allowed", Boolean(), primary_key=False, nullable=False, unique=False),
)
Index("ix_sessions_expires", metadata.tables["sessions"].c["expires"])
Index("ix_events_timestamp", metadata.tables["events"].c["timestamp"])
Index("ix_events_dst_ip", metadata.tables["events"].c["dst_ip"])
Index("ix_events_severity", metadata.tables["events"].c["severity"])
Index("ix_events_src_ip", metadata.tables["events"].c["src_ip"])
Index("ix_events_origin", metadata.tables["events"].c["origin"])
Index("ix_connections_source", metadata.tables["connections"].c["source"])
Index("ix_connections_target", metadata.tables["connections"].c["target"])
Index("ix_blocks_state", metadata.tables["blocks"].c["state"])
Index("ix_blocks_expires", metadata.tables["blocks"].c["expires"])
Index("ix_blocks_ip", metadata.tables["blocks"].c["ip"])
Index("ix_investigation_notes_ip", metadata.tables["investigation_notes"].c["ip"])
