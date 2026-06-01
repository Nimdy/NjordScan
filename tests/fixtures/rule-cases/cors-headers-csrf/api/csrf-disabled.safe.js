// SAFE: CSRF protection left enabled (the framework default).
import express from 'express';

const app = express();

export const authOptions = {
  csrf: true,
  session: { strategy: 'jwt' },
};

export default app;
