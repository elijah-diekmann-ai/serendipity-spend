# Railway Setup

Production deployment on Railway with 5 services.

## Services

| Service | Purpose | Start Command |
|---------|---------|---------------|
| **web** | FastAPI app (public) | `uvicorn serendipity_spend.main:app --host 0.0.0.0 --port $PORT` |
| **worker** | Celery background jobs | `celery -A serendipity_spend.worker.celery_app:celery_app worker --loglevel=INFO --concurrency=1` |
| **Postgres** | Primary database | (managed) |
| **Redis** | Celery broker | (managed) |
| **Bucket** | S3-compatible storage | (managed) |

## Why Bucket?

Uploads are written by `web` but processed by `worker`. Both services must share the same storage backend — Railway Bucket provides this.

## Environment Variables (Shared)

```bash
ENVIRONMENT=production
SECRET_KEY=<random-string>
DATABASE_URL=postgresql+psycopg://<full-postgres-url>
REDIS_URL=redis://default:<password>@redis.railway.internal:6379

# Storage
STORAGE_BACKEND=s3
S3_ENDPOINT_URL=${{ Bucket.ENDPOINT }}
S3_REGION=${{ Bucket.REGION }}
S3_BUCKET=${{ Bucket.BUCKET }}
S3_ACCESS_KEY_ID=${{ Bucket.ACCESS_KEY_ID }}
S3_SECRET_ACCESS_KEY=${{ Bucket.SECRET_ACCESS_KEY }}

# Google OAuth
GOOGLE_OAUTH_CLIENT_ID=<from-google-cloud>
GOOGLE_OAUTH_CLIENT_SECRET=<from-google-cloud>
GOOGLE_OAUTH_ALLOWED_DOMAIN=serendipitycapital.com
```

## Web Service Variables

```bash
INIT_ADMIN_EMAIL=admin@serendipitycapital.com
BASE_URL=https://<your-domain>.up.railway.app
```

## Pre-Deploy (web only)

```bash
alembic upgrade head
```

## Notes

- `ENVIRONMENT=production` → Celery uses Redis (not eager mode)
- `DATABASE_URL` must include `+psycopg` driver
- Hardcode `REDIS_URL` value (variable references sometimes fail for worker)
- Remove `INIT_ADMIN_EMAIL` after first login