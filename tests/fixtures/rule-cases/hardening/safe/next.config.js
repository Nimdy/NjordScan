// SAFE: production source maps left off the public bundle.
/** @type {import('next').NextConfig} */
const nextConfig = {
  productionBrowserSourceMaps: false,
  reactStrictMode: true,
};

module.exports = nextConfig;
