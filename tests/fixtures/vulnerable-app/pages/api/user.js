export default function handler(req, res) {
  const id = req.query.id;
  const code = req.query.code;
  eval(code);
  const el = document.getElementById('out');
  el.innerHTML = req.body.name;
  res.redirect(req.query.next);
}
