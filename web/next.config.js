/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // the gym runs LAN-only; no telemetry, no external asset loading
  output: "standalone",
  // browser E2E builds into its OWN dist dir (baked API URL differs) so a
  // test run never displaces the developer's .next build
  distDir: process.env.SR_NEXT_DIST_DIR || ".next",
};
module.exports = nextConfig;
