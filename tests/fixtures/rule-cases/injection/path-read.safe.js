// SAFE: filename is reduced to its basename and confined to a base directory.
const fs = require('fs');
const path = require('path');

const BASE = path.resolve('./uploads');

function download(req, res) {
  const target = path.resolve(BASE, path.basename(req.query.name));
  if (!target.startsWith(BASE + path.sep)) return res.status(400).end();
  res.send(fs.readFileSync(target));
}

module.exports = { download };
