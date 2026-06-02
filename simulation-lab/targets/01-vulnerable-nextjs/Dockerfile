FROM node:24-alpine

WORKDIR /app

# The demo DAST server is dependency-free, so we only need the source.
COPY server.js ./
COPY package.json ./

ENV PORT=3001
EXPOSE 3001

CMD ["node", "server.js"]
