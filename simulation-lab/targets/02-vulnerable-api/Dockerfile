# QuickNotes API — intentionally vulnerable lab target.
FROM node:24-alpine

WORKDIR /app

# Dependency-free (Node built-ins only) — no npm install, so the build is hermetic
# and works fully offline.
COPY . .

ENV NODE_ENV=production
ENV PORT=3002
EXPOSE 3002

CMD ["node", "server.js"]
