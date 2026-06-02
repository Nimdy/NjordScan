// VULNERABLE: cors() configured to allow every origin.
import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors({ origin: true, credentials: true }));

export default app;
