export function listen() {
  window.addEventListener('message', (event) => {
    const data = event.data;
    document.title = data.title;
    handleCommand(data.command);
  });
}
