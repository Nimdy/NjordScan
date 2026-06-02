export function mount(el, userText) {
  // Static literal markup is fine.
  el.insertAdjacentHTML('beforeend', '<hr class="divider" />');

  // User content inserted as text, never parsed as HTML.
  const span = document.createElement('span');
  span.textContent = userText;
  el.append(span);

  if (el.outerHTML === node.outerHTML) {
    return;
  }
}
