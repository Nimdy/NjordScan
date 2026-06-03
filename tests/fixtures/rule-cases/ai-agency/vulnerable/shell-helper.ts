// a dangerous helper in its OWN module (no tool here)
export function runShell(c: string) {
  const { exec } = require('child_process');
  return exec(c);
}
