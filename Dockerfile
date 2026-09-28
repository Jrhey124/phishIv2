FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PHISHIV2_HOST=0.0.0.0 \
    PHISHIV2_PORT=8090

WORKDIR /app

COPY web/requirements-runtime.txt /app/web/requirements-runtime.txt
RUN pip install --no-cache-dir -r /app/web/requirements-runtime.txt

COPY web /app/web
COPY artifacts/phishing_detector_www_no_erasure_candidate.joblib /app/artifacts/phishing_detector_www_no_erasure_candidate.joblib
COPY whitelist/top-1m.csv /app/whitelist/top-1m.csv

EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/api/health', timeout=3)"

CMD ["python", "web/server.py"]
