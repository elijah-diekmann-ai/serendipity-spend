FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-eng \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libpangoft2-1.0-0 \
        shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY Data /app/Data
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic
RUN pip install --no-cache-dir -e .

EXPOSE 8000

CMD ["uvicorn", "serendipity_spend.main:app", "--host", "0.0.0.0", "--port", "8000"]
