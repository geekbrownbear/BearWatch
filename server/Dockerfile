# Built from the repo root (context: .) so the intel/ data folder ships with the code.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    BEARWATCH_OVERRIDES_PATH=/srv/intel/cpe_overrides.json \
    BEARWATCH_POSTURE_RULES_PATH=/srv/intel/posture_rules.toml \
    BEARWATCH_LIFECYCLE_PATH=/srv/intel/windows_lifecycle.toml

# Pango for WeasyPrint (the monthly PDF report). Fonts come from bearwatch/web/static.
RUN apt-get update && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/server

# Dependencies first (cached layer), using a stub package so code edits don't reinstall them.
COPY server/pyproject.toml ./
COPY server/bearwatch/__init__.py ./bearwatch/__init__.py
RUN pip install --no-cache-dir . && pip uninstall -y bearwatch

COPY server/bearwatch ./bearwatch
COPY intel /srv/intel
RUN pip install --no-cache-dir --no-deps .

RUN useradd --system --uid 10001 bearwatch
USER bearwatch

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "bearwatch.api:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
