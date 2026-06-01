export function Vuln({ onRun }) {
  return (
    <div>
      <a href="javascript:doStuff()">Click me</a>
      <img src={"javascript:alert(1)"} alt="x" />
    </div>
  );
}
