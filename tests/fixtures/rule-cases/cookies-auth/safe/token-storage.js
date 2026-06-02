// Non-sensitive UI state in localStorage is fine. Should NOT fire.
export function saveTheme(theme) {
  localStorage.setItem('theme', theme);
}

export function saveSidebar(open) {
  localStorage.setItem('sidebarOpen', String(open));
}
