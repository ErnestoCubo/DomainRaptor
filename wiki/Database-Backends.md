# Database Backends

DomainRaptor stores scan history, watch targets and enrichment data in a
relational database. SQLite is used by default, but PostgreSQL and MySQL are
supported via SQLAlchemy + Alembic when you install the matching optional
extras.

## Default (SQLite)

No configuration required. The database lives at
`~/.domainraptor/domainraptor.db` and is initialised on first use by
`DatabaseManager`. The legacy `sqlite3`-based repositories
(`ScanRepository`, `WatchRepository`) are used.

## Selecting another backend

Set a SQLAlchemy URL via either:

- Environment variable: `DOMAINRAPTOR_DATABASE_URL=...`
- Config file (`~/.domainraptor/config.toml`): `database_url = "..."`

When `database_url` is non-`sqlite:`, DomainRaptor switches to the SQLAlchemy
Core-backed `SqlScanRepository` / `SqlWatchRepository` automatically (via
`domainraptor.storage.get_scan_repository`).

### PostgreSQL

Install the extra:

```bash
pip install "domainraptor[postgres]"
```

Example URL:

```toml
database_url = "postgresql+psycopg://user:password@localhost:5432/domainraptor"
```

### MySQL / MariaDB

Install the extra:

```bash
pip install "domainraptor[mysql]"
```

Example URL:

```toml
database_url = "mysql+pymysql://user:password@localhost:3306/domainraptor"
```

## Migrations

Schema changes are managed with Alembic. The repository ships with a baseline
migration that mirrors the legacy schema version 3.

```bash
# Apply all pending migrations against the configured DB
PYTHONPATH=src alembic upgrade head

# Inspect the current revision
PYTHONPATH=src alembic current

# Autogenerate a new revision after editing storage/_metadata.py
PYTHONPATH=src alembic revision --autogenerate -m "describe change"
```

The URL is resolved with this priority:

1. `-x url=...` Alembic CLI argument
2. `DOMAINRAPTOR_DATABASE_URL` environment variable
3. `sqlalchemy.url` in `alembic.ini` (left blank by default)
4. `AppConfig.resolve_database_url()` from the user's config

## Connection pooling

For non-SQLite engines, DomainRaptor enables `pool_pre_ping`, a base pool size
of 5 and `max_overflow=10`. These defaults are conservative; tune them per
deployment by passing your own URL with `?pool_size=...&max_overflow=...`
query parameters (SQLAlchemy reads them automatically).

For SQLite, `check_same_thread=False` is enabled so the orchestrator's
`ThreadPoolExecutor` can share a single connection without raising.

## Limitations

- The legacy `DatabaseManager` migration ladder (v1 → v3) is SQLite-only.
  Non-SQLite users must run `alembic upgrade head` once before first use
  (the `get_scan_repository` / `get_watch_repository` factories do this
  automatically via `init_schema()` for fresh databases).
- Cross-dialect ON DELETE CASCADE behaviour is emulated in
  `SqlScanRepository.delete()` by deleting child rows explicitly before the
  parent scan row.
