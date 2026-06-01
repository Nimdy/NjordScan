// Fully-hardened session cookie: httpOnly + secure + sameSite. Should NOT fire.
export function loginSafe(res, token) {
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });
}

// SameSite=None but paired with secure: true — allowed, should NOT fire.
export function loginCrossSite(res, token) {
  res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'none' });
}

// A non-session preference cookie without flags is fine and not our concern.
export function setTheme(res, theme) {
  res.cookie('theme', theme, { maxAge: 31536000 });
}
