// VULNERABLE: a wildcard frame-ancestors lets any site iframe these pages (clickjacking).
export default function handler(req, res) {
  res.setHeader('Content-Security-Policy', "frame-ancestors *");
  res.send('<h1>dashboard</h1>');
}
