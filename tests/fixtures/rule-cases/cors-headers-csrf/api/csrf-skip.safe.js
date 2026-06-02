// SAFE: no CSRF check is skipped; protection stays on by default.
export const authOptions = {
  providers: [],
  session: { strategy: 'database' },
};
