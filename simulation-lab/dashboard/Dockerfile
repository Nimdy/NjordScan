# Build context is the simulation-lab root (see docker-compose) so we can pull in
# the blue-team detector and reuse it as the single source of truth for alerts.
FROM python:3.12-slim

WORKDIR /app

# The dashboard server + its single-file UI.
COPY dashboard/server.py dashboard/index.html ./
# The real blue-team detector — imported by server.py so the dashboard and
# `make blueteam` always run the exact same detection rules.
COPY blueteam/detect.py ./detect.py

ENV LOG_DIR=/logs PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/healthz',timeout=2).read()==b'ok' else 1)"

CMD ["python", "server.py"]
