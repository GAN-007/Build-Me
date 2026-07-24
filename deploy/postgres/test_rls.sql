\set ON_ERROR_STOP on

INSERT INTO organizations(id,name,slug,status) VALUES
('00000000-0000-0000-0000-000000000001','Tenant One','tenant-one','active'),
('00000000-0000-0000-0000-000000000002','Tenant Two','tenant-two','active');

INSERT INTO users(id,organization_id,email,display_name,user_type,status) VALUES
('10000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','one@example.com','One','human','active'),
('10000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','two@example.com','Two','human','active');

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='build_me_app_test') THEN
        CREATE ROLE build_me_app_test NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END $$;

GRANT USAGE ON SCHEMA public, app TO build_me_app_test;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, identity_sessions, subscriptions, usage_events, entitlement_overrides, operational_events TO build_me_app_test;
GRANT EXECUTE ON FUNCTION app.current_organization_id(), app.current_user_id() TO build_me_app_test;

SET ROLE build_me_app_test;
SET app.organization_id = '00000000-0000-0000-0000-000000000001';
SET app.user_id = '10000000-0000-0000-0000-000000000001';

DO $$
DECLARE visible_count integer;
BEGIN
    SELECT count(*) INTO visible_count FROM users;
    IF visible_count <> 1 THEN
        RAISE EXCEPTION 'RLS visibility failed: expected 1 user, got %', visible_count;
    END IF;
    IF EXISTS (SELECT 1 FROM users WHERE organization_id='00000000-0000-0000-0000-000000000002') THEN
        RAISE EXCEPTION 'cross-tenant read was not blocked';
    END IF;
END $$;

DO $$
BEGIN
    BEGIN
        INSERT INTO users(id,organization_id,email,display_name,user_type,status)
        VALUES('10000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000002','blocked@example.com','Blocked','human','active');
        RAISE EXCEPTION 'cross-tenant insert unexpectedly succeeded';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;
END $$;

RESET ROLE;
