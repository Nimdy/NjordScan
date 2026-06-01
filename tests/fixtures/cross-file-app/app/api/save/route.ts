import { render, safeText } from '../../../lib/render';
export function POST(req) {
  const el = document.getElementById('out');
  render(el, req.body.html);     // CROSS-FILE XSS: req.body -> render() -> innerHTML (in lib/render.ts)
  safeText(el, req.body.name);   // safe: safeText writes textContent, not a sink
  render(el, '<b>static</b>');    // safe: constant argument, not tainted
}
