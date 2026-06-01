export function render(userInput, container) {
  // Static loader markup only — no dynamic content.
  document.write('<p>Loading…</p>');

  // Dynamic content goes in as text, never parsed as HTML.
  const el = document.createElement('div');
  el.textContent = userInput;
  container.appendChild(el);
}
