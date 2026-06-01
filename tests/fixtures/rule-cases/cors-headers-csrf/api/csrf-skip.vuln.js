// VULNERABLE: NextAuth's CSRF check is being skipped.
export const authOptions = {
  skipCSRFCheck: true,
  providers: [],
};
