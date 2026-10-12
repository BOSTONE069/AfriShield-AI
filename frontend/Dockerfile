FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    AFRISHIELD_API_BASE=http://backend:8000

WORKDIR /app

COPY frontend/requirements.txt /tmp/frontend-requirements.txt
RUN pip install --no-cache-dir --requirement /tmp/frontend-requirements.txt \
    && addgroup --system afrishield \
    && adduser --system --ingroup afrishield afrishield
RUN usermod --home /home/afrishield afrishield \
    && mkdir -p /home/afrishield \
    && chown -R afrishield:afrishield /home/afrishield

ENV PYTHONPATH=/app

COPY frontend /app/frontend
COPY scripts/container_healthcheck.py /app/container_healthcheck.py
RUN chown -R afrishield:afrishield /app

USER afrishield
EXPOSE 8501

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["python", "/app/container_healthcheck.py", "http://127.0.0.1:8501/_stcore/health"]

CMD ["streamlit", "run", "frontend/streamlit_app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
