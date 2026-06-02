export function mount(el, userHtml, node) {
  el.insertAdjacentHTML('beforeend', userHtml);
  node.outerHTML = buildMarkup(userHtml);
}
