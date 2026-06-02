// SAFE: cors() restricted to a named origin.
import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors({ origin: 'https://app.example.com', credentials: true }));

export default app;
