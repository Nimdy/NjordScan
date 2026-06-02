// auth.hardcoded-credentials: literal password comparison
export function checkAdmin(req) {
  if (req.body.password === 'admin') {
    return true;
  }
  return false;
}

// auth.hardcoded-credentials: reversed comparison
export function isRoot(password) {
  return 'rootpass123' == password;
}

// auth.hardcoded-basic-auth: hard-coded Basic header
export async function callApi() {
  return fetch('https://api.internal/data', {
    headers: { Authorization: 'Basic YWRtaW46c3VwZXJzZWNyZXQ=' },
  });
}

// auth.hardcoded-basic-auth: hard-coded Bearer token
export async function callApi2() {
  return fetch('https://api.internal/data', {
    headers: { Authorization: 'Bearer prod-token-9f8e7d6c5b4a3f2e1d0c' },
  });
}
