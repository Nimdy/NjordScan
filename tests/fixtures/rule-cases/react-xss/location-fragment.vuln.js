export function routeFromHash() {
  location.href = location.hash.slice(1);
  window.location.assign(location.search.replace('?next=', ''));
}
