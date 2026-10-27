"""Domain constraints and unique directed connection pairs."""

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("events") as batch:
        batch.create_check_constraint("ck_event_risk", "risk BETWEEN 0 AND 100")
        batch.create_check_constraint(
            "ck_event_origin", "origin IN ('simulation','replay','live')"
        )
    with op.batch_alter_table("devices") as batch:
        batch.create_check_constraint(
            "ck_device_criticality", "criticality BETWEEN 1 AND 5"
        )
        batch.create_check_constraint(
            "ck_device_vulnerability", "vulnerability BETWEEN 0 AND 10"
        )
    with op.batch_alter_table("connections") as batch:
        batch.create_unique_constraint("uq_connection_pair", ["source", "target"])
        batch.create_check_constraint("ck_connection_distinct", "source <> target")


def downgrade():
    with op.batch_alter_table("connections") as batch:
        batch.drop_constraint("ck_connection_distinct", type_="check")
        batch.drop_constraint("uq_connection_pair", type_="unique")
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("ck_device_vulnerability", type_="check")
        batch.drop_constraint("ck_device_criticality", type_="check")
    with op.batch_alter_table("events") as batch:
        batch.drop_constraint("ck_event_origin", type_="check")
        batch.drop_constraint("ck_event_risk", type_="check")
