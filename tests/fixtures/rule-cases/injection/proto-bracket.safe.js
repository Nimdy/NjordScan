// SAFE: dangerous keys rejected, or data stored in a Map.
function setField(req, store) {
  const key = String(req.body.key);
  const store2 = new Map();
  store2.set(key, req.body.value);
  return store2;
}

module.exports = { setField };
