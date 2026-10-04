/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // the gym runs LAN-only; no telemetry, no external asset loading
  output: "standalone",
};
module.exports = nextConfig;
