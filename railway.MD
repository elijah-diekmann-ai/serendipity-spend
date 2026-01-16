# Deploying Serendipity Spend on Railway (Beginner Guide)

This guide walks you through deploying the Serendipity Spend MVP to Railway with:

- **`web`**: FastAPI app (public)
- **`worker`**: Celery worker (background jobs)
- **PostgreSQL**: primary database
- **Redis**: Celery broker/result backend
- **Storage**: **Railway Bucket (S3-compatible)** (recommended for multi-service deployments)

Why storage matters: uploads are written by `web`, but processed by `worker`. If `web` and `worker` don’t share the same storage backend, extraction/export jobs will fail.

---

## 0) What you need before starting

- A Railway account: `https://railway.com`
- A GitHub account
- This repo pushed to GitHub (Railway deploys from your GitHub repo)

If you don’t have a GitHub repo yet:

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<you>/<your-repo>.git
git push -u origin main
```

---

## 1) Create a Railway project + the `web` service

1. Go to `https://railway.com/new`
2. Click **Deploy from GitHub repo**
3. Select your repo and confirm the deploy
4. Railway creates your first service. Rename it to **`web`** (click the tile → **Settings** → **Service Name**)

Railway should detect the repo’s `Dockerfile` automatically during build.

---

## 2) Add Postgres and Redis to the project

On the Railway canvas:

1. Click **+ New**
2. Add **PostgreSQL**
3. Add **Redis**
4. (Optional but recommended) Rename them to **`Postgres`** and **`Redis`** so the variable references in this guide match exactly

---

## 3) Add a Railway Bucket (recommended storage)

On the Railway canvas:

1. Click **+ New**
2. Add **Bucket**
3. Rename it to **`Bucket`** (so references in this guide match)

You’ll use this for uploaded PDFs and generated exports.

---

## 4) Create the `worker` service (Celery)

1. Click **+ New**
2. Choose **Empty Service**
3. Click the new service → **Settings**
4. Under **Service Source**, choose **Connect Repo** and select the same GitHub repo/branch
5. Rename this service to **`worker`**

This creates a second deployment target from the same codebase.

---

## 5) Set environment variables (shared + service-specific)

Railway supports **Shared Variables** (apply to all services) and **Service Variables** (only one service).

For this project:

- Put **most variables in Shared Variables** (so `web` and `worker` match)
- Put **bootstrap admin credentials** as **Service Variables** on `web` (and remove them after first login)

### 5.1 Shared Variables (recommended)

In Railway, open your project → **Variables** (the environment-level variables).

Add these:

```bash
# App
ENVIRONMENT=production
SECRET_KEY=<generate-a-random-string>

# Google OAuth (login)
GOOGLE_OAUTH_CLIENT_ID=<from-google-cloud>
GOOGLE_OAUTH_CLIENT_SECRET=<from-google-cloud>
GOOGLE_OAUTH_ALLOWED_DOMAIN=serendipitycapital.com

# Database (IMPORTANT: use psycopg driver)
DATABASE_URL=postgresql+psycopg://${{ Postgres.PGUSER }}:${{ Postgres.PGPASSWORD }}@${{ Postgres.PGHOST }}:${{ Postgres.PGPORT }}/${{ Postgres.PGDATABASE }}

# Celery / Redis
REDIS_URL=${{ Redis.REDIS_URL }}

# Storage (use Railway Bucket)
STORAGE_BACKEND=s3
S3_ENDPOINT_URL=${{ Bucket.ENDPOINT }}
S3_REGION=${{ Bucket.REGION }}
S3_BUCKET=${{ Bucket.BUCKET }}
S3_ACCESS_KEY_ID=${{ Bucket.ACCESS_KEY_ID }}
S3_SECRET_ACCESS_KEY=${{ Bucket.SECRET_ACCESS_KEY }}

# Optional OCR language(s) for Tesseract
# TESSERACT_LANG=eng
```

Notes:

- `ENVIRONMENT=production` ensures Celery **does not** run eagerly in-process; the `worker` will process jobs via Redis.
- `DATABASE_URL` must include `+psycopg` because this app uses `psycopg` (v3). Railway’s Postgres `DATABASE_URL` is usually `postgresql://...` (psycopg2-style), so we build our own from `PG*` vars.
- The `${{ ... }}` syntax is Railway’s variable reference/template syntax.
- Railway uses **staged changes**. After editing variables, click **Deploy** / **Deploy Changes** to apply them.
- For secrets, use Railway’s **Seal** option (recommended for `SECRET_KEY`, `INIT_ADMIN_PASSWORD`, and `S3_SECRET_ACCESS_KEY`).

### 5.2 `web` service variables (bootstrap admin)

To create your first login user automatically on startup:

1. Open the **`web`** service → **Variables**
2. Add:

```bash
INIT_ADMIN_EMAIL=you@example.com
INIT_ADMIN_PASSWORD=<choose-a-strong-password>
```

After you successfully log in once, **remove these two variables** and redeploy `web`.

If you are using Google OAuth, you can also set **only** `INIT_ADMIN_EMAIL` (the app will generate a random password internally).

### 5.3 `web` service variable (Base URL)

This app currently doesn’t rely heavily on `BASE_URL`, but set it anyway for future links/emails.

After you generate a public domain (Step 7), set on the `web` service:

```bash
BASE_URL=https://${{ RAILWAY_PUBLIC_DOMAIN }}
```

---

## 6) Configure commands (start + migrations)

### 6.1 `web` start command (FastAPI)

Open the **`web`** service → **Settings** → **Start Command** and set:

```bash
/bin/sh -c "exec uvicorn serendipity_spend.main:app --host 0.0.0.0 --port $PORT"
```

Why: Railway provides a `PORT` and expects your web service to listen on `0.0.0.0:$PORT`.

### 6.2 `web` pre-deploy command (database migrations)

Open the **`web`** service → **Settings** → **Pre-Deploy Command** and set:

```bash
alembic upgrade head
```

This runs migrations automatically on each deploy before the app starts.

### 6.3 `worker` start command (Celery worker)

Open the **`worker`** service → **Settings** → **Start Command** and set:

```bash
/bin/sh -c "exec celery -A serendipity_spend.worker.celery_app:celery_app worker --loglevel=INFO --concurrency=1"
```

---

## 7) Make the `web` service publicly accessible (domain)

1. Open the **`web`** service → **Settings**
2. Find **Networking → Public Networking**
3. Click **Generate Domain**

Once generated, you can visit:

- Portal UI: `https://<your-domain>/app`
- API docs: `https://<your-domain>/docs`

---

## 8) First-time smoke test (did it work?)

1. Visit `https://<your-domain>/app`
2. Log in with the admin credentials you set in `INIT_ADMIN_EMAIL` / `INIT_ADMIN_PASSWORD`
3. Create a claim
4. Upload a PDF bundle (try the included sample `Data/DC__OOP__05 Sep 2025.pdf`)
5. Confirm:
   - `web` logs show the upload request
   - `worker` logs show it picked up `extract_source_file`
   - extracted items appear in the claim UI after processing

If uploads/extraction never finishes, jump to **Troubleshooting → Worker not processing jobs**.

---

## Troubleshooting

### `web` deploys but your domain shows 502 / “Application failed to respond”

- Ensure `web` start command uses `$PORT`:
  - `/bin/sh -c "exec uvicorn ... --port $PORT"`
- Ensure it binds to `0.0.0.0` (not `127.0.0.1`)
- Check `web` logs for a crash on startup (often missing/invalid env vars)

### Migrations fail (`alembic upgrade head`)

- Confirm `DATABASE_URL` is set and includes `postgresql+psycopg://...`
- Confirm the `Postgres` service exists and is running
- Look at the `web` pre-deploy logs for the exact error

### Worker not processing jobs (uploads stuck in “processing”)

- Confirm `ENVIRONMENT` is **not** `dev`
- Confirm `REDIS_URL` points to `${{ Redis.REDIS_URL }}`
- Confirm the `worker` service is deployed and running
- Check `worker` logs for Redis connection errors

### Storage errors (uploads succeed but extraction/export fails)

- Confirm `STORAGE_BACKEND=s3` and the `S3_*` variables reference the Railway Bucket
- Confirm both `web` and `worker` see the same variables (use Shared Variables)

---

## Optional: “single-service” mode (simpler, not recommended for production)

If you want the simplest possible setup (no Redis, no worker), you can run Celery tasks eagerly by setting:

```bash
ENVIRONMENT=dev
```

In this mode, uploads/extraction/export run inside the `web` process (slower, blocks requests). This is okay for demos, but not recommended for real use.

---

## Appendix: All supported app environment variables

These are the environment variables this app understands (from `.env.example` and `src/serendipity_spend/core/config.py`), plus OCR-related variables:

### App + auth

- `ENVIRONMENT` (default: `dev`) — set to `production` on Railway if using `worker` + Redis.
- `SECRET_KEY` (default: `change-me`) — required in production (JWT signing key).
- `BASE_URL` (default: `http://localhost:8000`) — optional; recommended: `https://${{ RAILWAY_PUBLIC_DOMAIN }}` on `web`.
- `ACCESS_TOKEN_EXP_MINUTES` (default: `1440`) — optional; JWT lifetime.

### Database

- `DATABASE_URL` (default: `sqlite:///./serendipity.db`) — on Railway Postgres use `postgresql+psycopg://...`.

### Redis / Celery

- `REDIS_URL` (default: `redis://localhost:6379/0`) — required when `ENVIRONMENT != dev`.

### Storage (choose one)

**Local (not recommended for multi-service):**

- `STORAGE_BACKEND=local`
- `LOCAL_STORAGE_PATH` (default: `.local_storage`)

**S3-compatible (recommended for Railway `web` + `worker`):**

- `STORAGE_BACKEND=s3`
- `S3_ENDPOINT_URL`
- `S3_REGION`
- `S3_BUCKET`
- `S3_ACCESS_KEY_ID`
- `S3_SECRET_ACCESS_KEY`

### Bootstrap admin (web-only)

- `INIT_ADMIN_EMAIL` — if set with `INIT_ADMIN_PASSWORD`, creates an admin user on startup (remove after first login).
- `INIT_ADMIN_PASSWORD`

### OCR (optional)

- `TESSERACT_LANG` (default: `eng`) — Tesseract language(s), e.g. `eng+spa`.
