/** @type {import('next').NextConfig} */
// VULNERABLE next.config: several Next.js-specific footguns enabled at once.
module.exports = {
  poweredByHeader: true,
  productionBrowserSourceMaps: true,
  experimental: {
    serverActions: {
      allowedOrigins: ['*'],
    },
  },
  images: {
    dangerouslyAllowSVG: true,
  },
};
