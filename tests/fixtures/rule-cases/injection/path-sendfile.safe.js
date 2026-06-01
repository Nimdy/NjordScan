// SAFE: fixed root option and basename strip any ../ segments.
const express = require('express');
const path = require('path');
const router = express.Router();

router.get('/file', (req, res) => {
  const name = path.basename(req.query.path);
  res.sendFile(name, { root: path.resolve('./public/files') });
});

module.exports = router;
