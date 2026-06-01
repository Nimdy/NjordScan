// VULNERABLE: file read with a path taken from the request.
const fs = require('fs');
const path = require('path');

function download(req, res) {
  const data = fs.readFileSync('./uploads/' + req.query.name);
  res.send(data);
}

function streamFile(req, res) {
  const full = path.join('./uploads', req.params.file);
  fs.createReadStream(full).pipe(res);
}

module.exports = { download, streamFile };
