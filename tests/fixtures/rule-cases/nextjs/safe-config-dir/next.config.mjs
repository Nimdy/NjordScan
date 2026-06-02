/** @type {import('next').NextConfig} */
// SAFE next.config: hardened defaults; nothing dangerous toggled on.
const nextConfig = {
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  experimental: {
    serverActions: {
      allowedOrigins: ['app.example.com'],
    },
  },
  images: {
    dangerouslyAllowSVG: false,
    remotePatterns: [{ protocol: 'https', hostname: 'assets.example.com' }],
  },
};

export default nextConfig;
