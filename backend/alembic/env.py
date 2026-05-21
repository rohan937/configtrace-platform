"""Alembic migration environment.

Reads DATABASE_URL from the environment at runtime so the same alembic.ini
works inside Docker Compose and in local development without hardcoded
credentials.
"""

import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ── sys.path ─────────────────────────────────────────────────────────────────
# Add the backend root (the directory that contains `app/`) to sys.path so
# `from app.models import Base` resolves correctly when Alembic is run from
# any working directory.
_backend_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)

# ── Imports that depend on sys.path ──────────────────────────────────────────
from app.models import Base  # noqa: E402

# ── Alembic config ───────────────────────────────────────────────────────────
config = context.config

# Override sqlalchemy.url from the DATABASE_URL environment variable.
# This takes precedence over the placeholder value in alembic.ini.
_database_url = os.environ.get("DATABASE_URL")
if not _database_url:
    raise RuntimeError(
        "DATABASE_URL environment variable is not set. "
        "Copy .env.example to .env and fill in the value, "
        "or set the variable in your shell before running Alembic."
    )
config.set_main_option("sqlalchemy.url", _database_url)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# SQLAlchemy MetaData object for autogenerate support.
target_metadata = Base.metadata


# ── Migration runners ─────────────────────────────────────────────────────────


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no live DB connection).

    Generates SQL statements to stdout.  Useful for previewing a migration
    or applying it via a DBA.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        # NullPool: each migration run gets a fresh connection and releases it
        # immediately; avoids connection leaks in short-lived CLI invocations.
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
