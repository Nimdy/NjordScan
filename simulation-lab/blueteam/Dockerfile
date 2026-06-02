# Blue-team mini-SIEM — pure Python stdlib, no dependencies. It tails the access
# logs the vulnerable targets write to the shared /logs volume and raises
# MITRE-mapped alerts on attack signatures.
FROM python:3.12-slim

WORKDIR /app
COPY detect.py ./

ENV LOG_DIR=/logs
# Default to live-tail; `docker compose run --rm blueteam --once` overrides for a
# one-shot pass over the accumulated logs.
ENTRYPOINT ["python3", "detect.py"]
CMD ["--follow"]
