// VULNERABLE: ReDoS-prone regular expressions with nested quantifiers.

// fires: hardening.redos-regex
export const RE_LITERAL = /^(a+)+$/;

export function buildRe() {
  // fires: hardening.redos-regex (dynamic)
  return new RegExp('^(\\d+)+$');
}
