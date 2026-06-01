import { searchProducts, renderLabel } from '../../../lib/db';
import { paint } from '../../../lib/render';

export async function POST(req) {
  const body = req.body;
  // CROSS-FILE TAINT: req.body -> searchProducts() -> SQL sink (in lib/db.ts)
  const rows = await searchProducts(body.term);
  // CROSS-FILE TAINT: req.body -> paint() -> innerHTML (in lib/render.ts)
  const el = document.getElementById('out');
  paint(el, body.labelHtml);
  // calls lodash.template -> makes CVE-2021-23337 reachable/exploitable
  return renderLabel(body.template, rows);
}
