// cookie.missing-httponly: session cookie with no httpOnly
export function loginA(res, token) {
  res.cookie('session', token, { secure: true, sameSite: 'lax' });
}

// cookie.missing-secure: httpOnly present but no secure
export function loginB(res, token) {
  res.cookie('session', token, { httpOnly: true, sameSite: 'lax' });
}

// cookie.missing-samesite: httpOnly + secure but no sameSite
export function loginC(res, token) {
  res.cookie('auth', token, { httpOnly: true, secure: true });
}

// cookie.samesite-none-insecure: SameSite=None without Secure
export function loginD(res, token) {
  res.cookie('session', token, { httpOnly: true, sameSite: 'none' });
}
