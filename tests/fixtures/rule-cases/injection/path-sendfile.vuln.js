// VULNERABLE: res.sendFile given a request-controlled path.
const express = require('express');
const router = express.Router();

router.get('/file', (req, res) => {
  res.sendFile('./public/' + req.query.path);
});

router.get('/download', (req, res) => {
  res.download(req.params.file);
});

module.exports = router;
