-- Mojang fictional shop schema (paired 03+04, step 1/2).
-- All business data is fictional. Seeded from scenarios/mojang-seeds.json
-- (seed_version 1). The app and verifiers use the read-only `mojang_reader`
-- role (SELECT-only); the admin credential never leaves provisioning.
-- NOTE: 'synthetic-reader-pw' is a SYNTHETIC build-input placeholder.
-- Provisioning sets the real per-generation reader secret at deploy time;
-- images ship with no live credential (per-clone secrets arrive only through
-- the pinned management channel).
CREATE DATABASE IF NOT EXISTS mojang CHARACTER SET utf8mb4;
USE mojang;
CREATE TABLE IF NOT EXISTS purchases (
  purchase_id VARCHAR(32) PRIMARY KEY,
  game_id VARCHAR(32) NOT NULL,
  buyer VARCHAR(64) NOT NULL,
  price_cents INT NOT NULL
);
-- Stock MySQL 8.0 defaults to caching_sha2_password; the reader
-- account is pinned to mysql_native_password so every observer
-- (guest-local client and controller-direct) authenticates identically.
CREATE USER IF NOT EXISTS 'mojang_reader'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY 'synthetic-reader-pw';
GRANT SELECT ON mojang.* TO 'mojang_reader'@'127.0.0.1';
FLUSH PRIVILEGES;
