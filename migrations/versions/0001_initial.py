"""Initial schema. Metadata snapshot is frozen in schema_v1 for reproducibility."""

from alembic import op
from migrations.schema_v1 import metadata

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    metadata.create_all(bind=op.get_bind())


def downgrade():
    metadata.drop_all(bind=op.get_bind())
