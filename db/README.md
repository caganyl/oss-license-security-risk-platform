# Database Migrations

PostgreSQL 15+ is expected.

Run all pending migrations:

```sh
DATABASE_URL=postgres://user:password@localhost:5432/oss_risk ./db/migrate.sh up
```

Roll back applied migrations in reverse order:

```sh
DATABASE_URL=postgres://user:password@localhost:5432/oss_risk ./db/migrate.sh down
```

Migration state is stored in the target database in `schema_migrations`.
