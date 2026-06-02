module.exports = {
  typescript: { ignoreBuildErrors: true },   // ships type errors to prod
  eslint: { ignoreDuringBuilds: true },
  images: { domains: ['*'] },                 // any host can be proxied
  // no security headers configured
};
