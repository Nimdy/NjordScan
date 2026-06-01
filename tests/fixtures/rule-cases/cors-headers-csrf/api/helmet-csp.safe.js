// SAFE: Helmet's CSP is configured, not disabled.
import express from 'express';
import helmet from 'helmet';

const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        'script-src': ["'self'"],
        'object-src': ["'none'"],
        'base-uri': ["'self'"],
      },
    },
  })
);

export default app;
