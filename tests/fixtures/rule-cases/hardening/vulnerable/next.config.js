// VULNERABLE: production source maps published to the browser.
/** @type {import('next').NextConfig} */
const nextConfig = {
  // fires: hardening.source-map-shipped-to-prod
  productionBrowserSourceMaps: true,
  reactStrictMode: true,
};

module.exports = nextConfig;
