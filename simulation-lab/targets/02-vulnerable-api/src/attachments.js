'use strict';

const fs = require('fs');
const path = require('path');

const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');

// VULNERABLE: builds a filesystem path directly from the request and reads it.
// A `name` like ../../etc/passwd escapes the uploads folder (path traversal).
function readAttachment(req) {
  const target = path.join(UPLOAD_DIR, req.query.name);
  return fs.readFileSync(target, 'utf8');
}

// VULNERABLE: streams a request-controlled file straight back to the client.
function streamAttachment(req, res) {
  const filePath = path.join(UPLOAD_DIR, req.params.file);
  const stream = fs.createReadStream(filePath);
  stream.pipe(res);
}

module.exports = { readAttachment, streamAttachment, UPLOAD_DIR };
