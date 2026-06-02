// VULNERABLE: the cors origin callback approves whatever origin called in.
import cors from 'cors';

export const corsMiddleware = cors({
  origin: function (origin, callback) {
    callback(null, origin);
  },
  credentials: true,
});
