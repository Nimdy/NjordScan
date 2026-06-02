// SAFE: parse data with JSON.parse, never rebuild functions from input.

export function loadCookie(req) {
  const obj = JSON.parse(req.cookies.session || '{}');
  return MySchema.parse(obj); // validated plain data
}

export function compute(input) {
  // pure data transform, no vm, no eval
  return input.values.reduce((a, b) => a + b, 0);
}
