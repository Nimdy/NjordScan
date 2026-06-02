// VULNERABLE: insecure deserialization.
const serialize = require('node-serialize');
const vm = require('vm');

export function loadCookie(req) {
  // fires: hardening.insecure-deserialization (node-serialize)
  const obj = serialize.unserialize(req.cookies.session);
  return obj;
}

export function runUser(req) {
  // fires: hardening.insecure-deserialization (vm on input)
  return vm.runInNewContext(req.body.code, {});
}
