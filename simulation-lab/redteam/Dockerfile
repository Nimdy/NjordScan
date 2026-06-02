# NjordScan Simulation Lab — RED TEAM attacker container.
#
# A tiny adversary box that joins the lab bridge network and runs the
# adversary-emulation playbook (attack.sh) against the live vulnerable targets,
# reaching them by service name: http://web:3001 and http://api:3002.
#
# Build:
#   docker build -t njordlab-redteam:local ./redteam
#
# Run on the lab network (targets must be up):
#   docker run --rm --network njordscan-lab_labnet njordlab-redteam:local
#
# Or point it at the published host ports from anywhere:
#   docker run --rm -e WEB_URL=http://host.docker.internal:3001 \
#                   -e API_URL=http://host.docker.internal:3002 \
#                   njordlab-redteam:local
FROM alpine:3.20

# Toolset: curl + bash are the hard requirement (curl-only mode always works).
# nmap is added for the recon technique; if the package index is unreachable
# (fully offline build), the build still succeeds and attack.sh transparently
# falls back to a curl banner grab and prints a note saying so.
RUN apk add --no-cache curl bash \
    && (apk add --no-cache nmap || echo "WARN: nmap unavailable (offline) - attack.sh will run in curl-only recon mode")

WORKDIR /redteam

# The playbooks. Copied last so edits don't bust the package-install layer.
# attack.sh = the lab's fixed targets; attack-byo.sh = generic, for your own target.
COPY attack.sh attack-byo.sh /redteam/
RUN chmod +x /redteam/attack.sh /redteam/attack-byo.sh

# Default to the docker-network service names; override with -e at run time so
# the same image also works against localhost:3001 / localhost:3002.
ENV WEB_URL=http://web:3001 \
    API_URL=http://api:3002

ENTRYPOINT ["/redteam/attack.sh"]
