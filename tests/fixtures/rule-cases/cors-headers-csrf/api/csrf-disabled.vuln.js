// VULNERABLE: CSRF protection explicitly turned off on a cookie-auth app.
import express from 'express';

const app = express();

export const authOptions = {
  csrf: false,
  session: { strategy: 'jwt' },
};

export default app;
