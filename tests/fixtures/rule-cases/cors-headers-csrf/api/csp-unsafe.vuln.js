// VULNERABLE: CSP weakened with both unsafe-inline and unsafe-eval.
export default function handler(req, res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'"
  );
  res.send('<h1>hello</h1>');
}
