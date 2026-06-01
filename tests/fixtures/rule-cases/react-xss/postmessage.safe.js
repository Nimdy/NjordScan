export function listen() {
  window.addEventListener('message', (event) => {
    if (event.origin !== 'https://trusted.example.com') return;
    const data = event.data;
    document.title = data.title;
    handleCommand(data.command);
  });
}
