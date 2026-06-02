# The NjordScan scanner, containerized — it joins the lab network and scans the
# vulnerable target services LIVE (DAST) as well as their mounted source (static).
# Build context is the REPO ROOT (see docker-compose.yml) so it installs the local
# package straight from source.
FROM python:3.12-slim

# git is needed for the Keystone (commit-history) demo + --diff mode.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip

WORKDIR /opt/njordscan
COPY pyproject.toml README.md ./
COPY njordscan ./njordscan
# [dynamic] pulls httpx so --url DAST works from inside the container.
RUN pip install --no-cache-dir '.[dynamic]'

# Scans run against the lab mounted at /lab; keep the user-data cache off the mount.
WORKDIR /lab
ENV NJORDSCAN_HOME=/tmp/njordscan-home
ENTRYPOINT ["njordscan"]
CMD ["doctor"]
