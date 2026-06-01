import type { NextApiRequest, NextApiResponse } from 'next';

const ALLOWED = new Set(['https://app.example.com']);

// SAFE: echoes back only an allow-listed origin, never the wildcard.
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const origin = req.headers.origin ?? '';
  if (ALLOWED.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.status(200).json({ user: 'me' });
}
