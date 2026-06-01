// SAFE: frame-ancestors locked to same origin, plus X-Frame-Options.
export default function handler(req, res) {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'self'");
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.send('<h1>dashboard</h1>');
}
