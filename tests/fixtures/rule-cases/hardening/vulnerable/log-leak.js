// VULNERABLE: secrets and request bodies written to the logs.

export function login(req) {
  const password = req.body.password;
  // fires: info-leak.console-logs-secret
  console.log('user password is', password);

  const apiKey = process.env.SOME_KEY;
  // fires: info-leak.console-logs-secret
  console.error('using api_key', apiKey);

  // fires: info-leak.console-logs-request-body
  console.log('incoming request', req.body);
}
