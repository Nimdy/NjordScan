// auth.middleware-bypass: guard hard-wired to true
export const isAuthenticated = (req) => true;

// auth.middleware-bypass: return true with a bypass comment
export function requireLogin(req, res, next) {
  return true; // TODO re-enable auth before launch
}

// auth.middleware-bypass: commented-out auth middleware
// app.use(requireAuth);
app.get('/admin', adminHandler);
