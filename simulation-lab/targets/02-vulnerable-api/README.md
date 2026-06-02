# QuickNotes API (vulnerable lab target)

A small Node JSON API used as the primary **live DAST target** for the NjordScan
simulation lab. It runs on the built-in `http` module with **zero npm
dependencies**, so `node server.js` works out of the box.

> ⚠️ Intentionally insecure. Do not deploy.

## Run

```bash
node server.js          # listens on PORT (default 3002)
# or
PORT=3002 npm start
# or
docker build -t quicknotes . && docker run -p 3002:3002 quicknotes
```

## Endpoints (and the issue each one demonstrates)

| Method | Route            | Issue                                                  |
|--------|------------------|--------------------------------------------------------|
| GET    | `/`              | index / health                                         |
| GET    | `/search?q=`     | Reflected XSS (echoes `q` unescaped into `text/html`)  |
| GET    | `/go?url=`       | Open redirect (302 `Location:` to the raw `url`)       |
| POST   | `/login`         | Sets `session` cookie with no HttpOnly/Secure/SameSite |
| POST   | `/legacy/login`  | Same insecure cookie via express-style `res.cookie`    |
| POST   | `/api/chat`      | Unauthenticated AI endpoint, no rate limit (denial-of-wallet) |
| GET    | `/notes?owner=`  | SQL injection (template literal)                       |
| GET    | `/notes/search?title=` | SQL injection (string concat)                    |
| DELETE | `/notes/:id`     | SQL injection (DELETE)                                  |
| GET    | `/attachments?name=` | Path traversal (`../`)                             |
| GET    | `/crash?payload=`| Verbose error / stack trace leak (500)                 |

Every response is missing the usual security headers (no CSP, HSTS,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and advertises its
version via `X-Powered-By`.
