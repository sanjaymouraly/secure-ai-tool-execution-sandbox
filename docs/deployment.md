# Deployment

## Deployment modes

| Mode | Use case | Isolation |
| ---- | -------- | --------- |
| Local workstation | Development and evaluation | Docker Engine on the host |
| Compose (single host) | A small team, a single machine | Docker Engine on the host |
| Compose behind a proxy | A real deployment | Docker Engine + a TLS reverse proxy |
| Multi-host | A larger organisation | A dedicated host per control plane, ideally with gVisor or a microVM |

## Principles

* **Bind to the loopback by default.** The API and the dashboard listen on
  `127.0.0.1`. Exposing them is an explicit decision.
* **Least privilege.** The control plane runs as an unprivileged user with a
  read-only root filesystem, all capabilities dropped and
  `no-new-privileges`.
* **The Docker socket is the crown jewel.** Only the control plane container
  can reach it, and sandbox workers never do.
* **Secrets come from the environment**, never from the repository and never
  from the image.
* **The workspace is mounted read-only** into the control plane.

## Compose

### Development

```bash
cp .env.example .env
python -c "import secrets; print('SAXIS_SECRET_KEY=' + secrets.token_urlsafe(48))" >> .env
python -c "from cryptography.fernet import Fernet; print('SAXIS_PROVIDER_SECRET_KEY=' + Fernet.generate_key().decode())" >> .env

docker build -t secure-ai-sandbox-runner:latest -f docker/sandbox/Dockerfile .
docker compose up --build -d
```

| Service | Address |
| ------- | ------- |
| Dashboard | <http://127.0.0.1:8080> |
| API | <http://127.0.0.1:8000/api/docs> |
| Health | <http://127.0.0.1:8000/health> |

### Production

```bash
export SAXIS_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export SAXIS_PROVIDER_SECRET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
export SAXIS_BOOTSTRAP_ADMIN_PASSWORD="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
export SAXIS_ALLOWED_ORIGINS="https://sandbox.example.com"

docker compose -f docker-compose.prod.yml up -d --build
```

The production compose file:

* does not publish any port — only the reverse proxy reaches the services;
* sets `SAXIS_ENVIRONMENT=production`, which makes the application refuse to
  start without an explicit secret, without multi-user authentication and
  without the Docker sandbox backend;
* runs both containers with `read_only: true`, `cap_drop: ALL` and
  `no-new-privileges`;
* mounts the workspace read-only and stores the database in a named volume.

## TLS and remote exposure

The service speaks plain HTTP. Terminate TLS in front of it.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name sandbox.example.com;

    ssl_certificate     /etc/letsencrypt/live/sandbox.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/sandbox.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    client_max_body_size 4m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name sandbox.example.com;
    return 301 https://$host$request_uri;
}
```

### Before you open the firewall

1. Set a strong `SAXIS_SECRET_KEY` and `SAXIS_BOOTSTRAP_ADMIN_PASSWORD`.
2. Change the bootstrap password after the first sign-in.
3. Set `SAXIS_ALLOWED_ORIGINS` to the exact public origin.
4. Set `SAXIS_PROVIDER_SECRET_KEY` so provider credentials are encrypted.
5. Consider `SAXIS_ALLOW_REGISTRATION=false` (the default) and create the
   accounts you need.
6. Put the audit export on a schedule and store it outside the host.
7. Restrict the Docker socket: a rootful daemon is root-equivalent on the
   host. Use a **rootless** daemon, or a dedicated host that runs nothing
   else.

> The application never trusts `X-Forwarded-For` unless a proxy is explicitly
> trusted, so the rate limiter cannot be bypassed with a forged header by
> default. If you terminate TLS in front of the service, keep that default.

## Database

### SQLite (default)

Suitable for a single control plane. The file lives in a named volume.

```dotenv
SAXIS_DATABASE_URL=sqlite:////app/data/sandbox.db
```

### PostgreSQL (multi-user deployment)

```dotenv
SAXIS_DATABASE_URL=postgresql+psycopg://saxis:<password>@db:5432/saxis
```

Add the driver:

```bash
pip install "psycopg[binary]"
```

and add it to `backend/requirements.txt`. Apply the migrations:

```bash
cd backend && alembic upgrade head
```

The schema is portable SQLAlchemy; treat the first PostgreSQL deployment as
unverified (see `docs/limitations.md`).

## Migrations

```bash
cd backend

alembic upgrade head                       # apply
alembic downgrade -1                       # roll back one revision
alembic revision --autogenerate -m "..."    # create a revision
alembic current                            # what is applied
alembic history                             # the revision graph
```

The application also creates the tables with `create_all` on startup, so a
fresh development database works without running Alembic. **Use Alembic for
anything you care about.**

## Operational runbook

### Health

```bash
curl -fsS http://127.0.0.1:8000/health
curl -fsS http://127.0.0.1:8000/ready
```

`/ready` returns `503` when the database is unreachable and reports the
sandbox posture.

### Logs

```bash
docker compose logs -f backend
```

The logs are structured JSON with credentials redacted. Every request carries
an `X-Request-ID` that also appears in the log record.

### Audit export

```bash
curl -fsS "http://127.0.0.1:8000/api/v1/audit/export?fmt=json&limit=10000" \
  -H "Authorization: Bearer $TOKEN" -o audit-$(date +%F).json
```

Then verify the chain of the export:

```bash
curl -fsS http://127.0.0.1:8000/api/v1/audit/verify -H "Authorization: Bearer $TOKEN"
```

### Retention

```bash
curl -X DELETE http://127.0.0.1:8000/api/v1/audit/retention -H "Authorization: Bearer $TOKEN"
```

Applies `SAXIS_AUDIT_RETENTION_DAYS`. Note that a retention purge breaks the
chain by design — export the trail first if the evidence matters.

### Revoking every session grant

```bash
curl -X POST http://127.0.0.1:8000/api/v1/approvals/grants/revoke \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
```

### Upgrading

```bash
git pull
docker build -t secure-ai-sandbox-runner:latest -f docker/sandbox/Dockerfile .
cd backend && alembic upgrade head
docker compose -f docker-compose.prod.yml up -d --build
```

## Backups

| What | Where | How |
| ---- | ----- | --- |
| Database | `backend-data` volume or PostgreSQL | `pg_dump`, or a volume snapshot |
| Audit trail | inside the database | Export to an append-only store on a schedule |
| Artifacts | `backend-data` volume | Volume snapshot |
| Workspace | host volume | It is read-only for the control plane, so back it up like any other data |
| Policy document | `backend/policies/default.yaml` | It is in the repository; every change is also stored in the `policy_documents` table |

## Cost control

| Setting | Effect |
| ------- | ------ |
| `SAXIS_BUDGET_SESSION_USD` | The maximum estimated spend for one session |
| `SAXIS_BUDGET_DAILY_USD` | The maximum estimated spend per day |
| `SAXIS_AGENT_MAX_STEPS` | The maximum number of model round trips per request |
| `SAXIS_PROVIDER_MAX_TOKENS` | The maximum tokens per provider call |

The budget guard refuses a call that would exceed the session budget and
reports the reason. The figures are estimates based on published list prices;
they are not a hard cap on the provider's invoice.

## Hardening checklist

- [ ] `SAXIS_SECRET_KEY` is set, random and not in the repository
- [ ] `SAXIS_PROVIDER_SECRET_KEY` is set
- [ ] The bootstrap administrator password was changed
- [ ] `SAXIS_ALLOW_REGISTRATION=false`
- [ ] `SAXIS_ALLOWED_ORIGINS` lists only the real origins
- [ ] The service binds to `127.0.0.1` behind a TLS proxy
- [ ] The Docker daemon runs rootless, or the host runs nothing else
- [ ] The workspace is mounted read-only
- [ ] The audit trail is exported on a schedule
- [ ] `SAXIS_ENVIRONMENT=production`
- [ ] The sandbox image is rebuilt and versioned with the release
