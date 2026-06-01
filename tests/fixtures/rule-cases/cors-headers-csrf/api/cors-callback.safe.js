// SAFE: the callback checks the origin against an allowlist first.
import cors from 'cors';

const allowed = ['https://app.example.com'];

export const corsMiddleware = cors({
  origin: function (origin, callback) {
    if (!origin || allowed.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Origin not allowed'));
    }
  },
  credentials: true,
});
