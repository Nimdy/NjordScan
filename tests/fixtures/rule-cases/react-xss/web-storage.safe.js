export function savePrefs(theme, locale) {
  // Non-sensitive UI preferences only — safe to persist.
  localStorage.setItem('theme', theme);
  localStorage.setItem('locale', locale);
  // The session token lives in an HttpOnly cookie the server sets; JS never sees it.
}
