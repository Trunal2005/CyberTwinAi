from alembic import context
from backend.db import Base, engine
from sqlalchemy import pool

if context.is_offline_mode():
    context.configure(
        url=str(engine.url), target_metadata=Base.metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    with engine.connect() as connection:
        if engine.dialect.name == "sqlite":
            # Batch recreation of referenced tables requires FK checks outside DDL.
            # Disable only on this offline maintenance connection, then validate all rows.
            connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
            connection.commit()
        context.configure(
            connection=connection, target_metadata=Base.metadata, render_as_batch=True
        )
        with context.begin_transaction():
            context.run_migrations()
        if engine.dialect.name == "sqlite":
            if connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("Migration produced foreign-key violations")
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()
