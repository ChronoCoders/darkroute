import type { NextConfig } from "next";

// Every browser request to /api/* is proxied server-side to the
// authority. Direct browser-to-authority requests are deliberately
// avoided so the authority never needs CORS middleware (ARCHITECTURE
// §6.2). The AUTHORITY_URL env var points at the authority service;
// in development that is typically http://localhost:3001 and in
// production it is the Cloudflare-fronted authority endpoint.
const AUTHORITY_URL = process.env.AUTHORITY_URL ?? "http://localhost:3001";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${AUTHORITY_URL}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
