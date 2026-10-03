-- Dev-bootstrap of the two DB roles inside docker-compose (the production R740
-- equivalent is run once by Drew; migrations target the app role's grants).
-- Owner role is created by the postgres image initdb (POSTGRES_USER=sr_owner).
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sr_app') THEN
        CREATE ROLE sr_app LOGIN PASSWORD 'devapp';
    END IF;
END $$;
