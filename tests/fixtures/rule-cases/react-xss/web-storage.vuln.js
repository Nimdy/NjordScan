export function saveSession(jwt, apiKey) {
  localStorage.setItem('authToken', jwt);
  sessionStorage['api_key'] = apiKey;
}
