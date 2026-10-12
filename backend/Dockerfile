FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    USE_LLM=false \
    USE_LLM_REPORTS=false

WORKDIR /app

COPY backend/requirements.txt /tmp/backend-requirements.txt
RUN pip install --no-cache-dir --requirement /tmp/backend-requirements.txt \
    && addgroup --system afrishield \
    && adduser --system --ingroup afrishield afrishield

COPY backend /app/backend
COPY samples /app/samples
COPY scripts/container_healthcheck.py /app/container_healthcheck.py
RUN mkdir -p /app/data && chown -R afrishield:afrishield /app/data

USER afrishield
EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "/app/container_healthcheck.py", "http://127.0.0.1:8000/ready"]

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
