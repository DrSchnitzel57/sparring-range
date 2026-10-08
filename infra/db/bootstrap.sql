-- Dev-bootstrap of the two DB roles inside docker-compose (the production R740
-- equivalent is run once by Drew; migrations target the app role's grants).
-- Owner role is created by the postgres image initdb (POSTGRES_USER=sr_owner).
--
-- The app-role password arrives via `psql -v app_pw=...` interpolated by
-- compose from SR_DEV_APP_PASSWORD — NEVER hardcoded here: a fixed dev
-- password silently diverges from the credentials the API is given, and the
-- stack then "works" only with the committed default (audit: no secrets in
-- Git, no implicit shared defaults). Passwords must not contain whitespace
-- (compose folds the command line).
\set ON_ERROR_STOP on
SELECT format('CREATE ROLE sr_app LOGIN PASSWORD %L', :'app_pw')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sr_app')\gexec
ALTER ROLE sr_app LOGIN PASSWORD :'app_pw';
