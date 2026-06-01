// SAFE: log ids and booleans, never the secret values or full bodies.

export function login(req) {
  const result = authenticate(req.body.email, req.body.password);
  console.log('login attempt', { email: req.body.email, ok: result.success });

  // referencing a field name, not logging the value
  const keyName = 'api_key';
  console.log('using credential', { keyName });

  // logging a specific safe field, not the whole body
  console.log('signup', { email: req.body.email });
  return result;
}
