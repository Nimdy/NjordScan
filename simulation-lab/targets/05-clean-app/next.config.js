/**
 * Next.js configuration for the Secure Notes app.
 *
 * Security headers are applied to every route. The Content-Security-Policy is
 * deliberately strict: it allows scripts and styles only from our own origin.
 * We rely on Next.js's built-in script handling rather than inline scripts, so
 * a tight policy does not break the app.
 */

/** @type {Array<{ key: string, value: string }>} */
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      'upgrade-insecure-requests',
    ].join('; '),
  },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Do not advertise the framework to attackers.
  poweredByHeader: false,
  // Fail the build on type/lint errors instead of shipping them to production.
  typescript: { ignoreBuildErrors: false },
  eslint: { ignoreDuringBuilds: false },
  // Only optimise images we host ourselves.
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'images.secure-notes.example' },
    ],
  },
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ];
  },
};

module.exports = nextConfig;
