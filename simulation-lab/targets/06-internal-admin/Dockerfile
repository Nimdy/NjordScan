FROM node:24-alpine

WORKDIR /app

# Dependency-free, so we only need the source.
COPY server.js ./
COPY package.json ./

ENV PORT=9000
EXPOSE 9000

CMD ["node", "server.js"]
