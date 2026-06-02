// Writes its second parameter straight to innerHTML — an XSS sink in another module.
export function paint(el: HTMLElement, html: string) {
  el.innerHTML = html;
}
