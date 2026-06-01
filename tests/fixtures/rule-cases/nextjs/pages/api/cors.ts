import type { NextApiRequest, NextApiResponse } from 'next';

// VULNERABLE: wildcard CORS lets any website read this endpoint's responses.
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.status(200).json({ user: 'me' });
}
