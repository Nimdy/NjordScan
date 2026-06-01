// auth.jwt-in-localstorage: token written to localStorage
export function saveLogin(jwt) {
  localStorage.setItem('access_token', jwt);
}

// auth.jwt-in-localstorage: bracket-assignment form
export function saveSession(value) {
  sessionStorage['authToken'] = value;
}
