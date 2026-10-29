"""Nullable network observations and explicit prevention correlation.

Existing Event rows retain their evidence. No historical measurements are invented.
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = depends_on = None


def upgrade():
    op.add_column("devices", sa.Column("segment", sa.String(80)))
    op.add_column("access_rules", sa.Column("allowed_ports", sa.JSON))
    op.add_column("access_rules", sa.Column("protocol", sa.String(20)))
    op.create_table(
        "network_flows",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("origin", sa.String(20), nullable=False),
        sa.Column("sensor", sa.String(80), nullable=False),
        sa.Column("sensor_flow_id", sa.String(100)),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", sa.String(45), nullable=False),
        sa.Column("dst_ip", sa.String(45), nullable=False),
        sa.Column("src_port", sa.Integer),
        sa.Column("dst_port", sa.Integer),
        sa.Column("ip_version", sa.Integer, nullable=False),
        sa.Column("protocol", sa.String(20), nullable=False),
        sa.Column("app_protocol", sa.String(80)),
        sa.Column("packets", sa.BigInteger),
        sa.Column("bytes_src", sa.BigInteger),
        sa.Column("bytes_dst", sa.BigInteger),
        sa.Column("total_bytes", sa.BigInteger),
        sa.Column("duration", sa.Float),
        sa.Column("state", sa.String(40)),
        sa.Column("tcp_flags", sa.String(80)),
        sa.Column("availability", sa.JSON, nullable=False),
        sa.Column("limitations", sa.JSON, nullable=False),
        sa.Column("risk", sa.Integer, nullable=False),
    )
    for name in [
        "origin",
        "sensor",
        "first_seen",
        "last_seen",
        "src_ip",
        "dst_ip",
        "protocol",
    ]:
        op.create_index("ix_network_flows_" + name, "network_flows", [name])
    with op.batch_alter_table("events") as batch:
        batch.add_column(sa.Column("flow_id", sa.String(64)))
        batch.add_column(sa.Column("record_key", sa.String(64)))
        batch.add_column(sa.Column("observation", sa.JSON))
        batch.add_column(sa.Column("detection", sa.JSON))
        batch.create_foreign_key("fk_events_flow", "network_flows", ["flow_id"], ["id"])
        batch.create_unique_constraint("uq_events_record_key", ["record_key"])
        batch.create_index("ix_events_flow_id", ["flow_id"])
    op.create_table(
        "prevention_decisions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("event_id", sa.Integer, sa.ForeignKey("events.id"), nullable=False),
        sa.Column("flow_id", sa.String(64), sa.ForeignKey("network_flows.id")),
        sa.Column("block_id", sa.Integer, sa.ForeignKey("blocks.id")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("policy", sa.String(30), nullable=False),
        sa.Column("outcome", sa.String(50), nullable=False),
        sa.Column("steps", sa.JSON, nullable=False),
    )
    for name in ["event_id", "flow_id", "block_id"]:
        op.create_index(
            "ix_prevention_decisions_" + name, "prevention_decisions", [name]
        )
    op.create_index(
        "ix_events_correlation",
        "events",
        ["src_ip", "origin", "detection_source", "timestamp"],
    )


def downgrade():
    op.drop_index("ix_events_correlation", table_name="events")
    op.drop_table("prevention_decisions")
    with op.batch_alter_table("events") as batch:
        batch.drop_index("ix_events_flow_id")
        batch.drop_constraint("fk_events_flow", type_="foreignkey")
        batch.drop_constraint("uq_events_record_key", type_="unique")
        for name in ["detection", "observation", "record_key", "flow_id"]:
            batch.drop_column(name)
    op.drop_table("network_flows")
    with op.batch_alter_table("access_rules") as batch:
        batch.drop_column("allowed_ports")
        batch.drop_column("protocol")
    with op.batch_alter_table("devices") as batch:
        batch.drop_column("segment")
