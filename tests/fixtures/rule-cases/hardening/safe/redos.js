// SAFE: bounded, non-nested regular expressions.

export const RE_EMAIL = /^[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,255}\.[a-z]{2,}$/i;

export function buildRe() {
  return new RegExp('^[0-9]{1,10}$');
}
