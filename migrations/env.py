"""Alembic environment for DomainRaptor.

Resolves the database URL from (in order of precedence):

1. ``-x url=...`` command-line override (e.g. ``alembic -x url=sqlite:///x.db upgrade head``).
2. ``DOMAINRAPTOR_DATABASE_URL`` environment variable.
3. ``sqlalchemy.url`` from alembic.ini, if set.
4. :meth:`AppConfig.resolve_database_url` (default: sqlite at ``~/.domainraptor/data.db``).

``target_metadata`` is wired to the SQLAlchemy schema mirror in
:mod:`domainraptor.storage._metadata` so ``alembic revision --autogenerate``
diffs against it.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from domainraptor.core.config import AppConfig
from domainraptor.storage._metadata import metadata as target_metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _resolve_url() -> str:
    x_args = context.get_x_argument(as_dictionary=True)
    if "url" in x_args:
        return x_args["url"]
    env_url = os.environ.get("DOMAINRAPTOR_DATABASE_URL")
    if env_url:
        return env_url
    ini_url = config.get_main_option("sqlalchemy.url")
    if ini_url:
        return ini_url
    return AppConfig().resolve_database_url()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DBAPI)."""
    context.configure(
        url=_resolve_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode using a real Engine."""
    section = config.get_section(config.config_ini_section, {}) or {}
    section["sqlalchemy.url"] = _resolve_url()

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        is_sqlite = connection.dialect.name == "sqlite"
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=is_sqlite,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
