export function render(target: HTMLElement, value: string) {
  target.innerHTML = value;          // sink — param `value` (index 1)
}
export function safeText(target: HTMLElement, value: string) {
  target.textContent = value;        // NOT a sink
}
