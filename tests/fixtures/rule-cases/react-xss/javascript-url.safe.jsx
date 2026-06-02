export function Safe({ onRun, url }) {
  return (
    <div>
      <button type="button" onClick={onRun}>Run</button>
      <a href="https://example.com/help">Help</a>
      <a href="/dashboard">Dashboard</a>
      <img src={url} alt="x" />
    </div>
  );
}
