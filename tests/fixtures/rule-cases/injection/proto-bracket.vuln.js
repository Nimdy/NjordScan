// VULNERABLE: object key taken straight from the request (bracket assignment).
function setField(req, store) {
  store[req.body.key] = req.body.value;
  return store;
}

module.exports = { setField };
