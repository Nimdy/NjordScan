export function routeFromHash() {
  const next = decodeURIComponent(location.hash.slice(1));
  // Only same-site paths: must start with a single "/" (not "//").
  if (/^\/(?!\/)/.test(next)) {
    location.assign(next);
  }
  // Reading the hash for non-navigation use is fine.
  const tab = location.hash.slice(1) || 'home';
  return tab;
}
