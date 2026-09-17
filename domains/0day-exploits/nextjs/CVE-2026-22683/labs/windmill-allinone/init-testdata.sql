-- Test data for Windfall path traversal dumps
-- Inserted after Windmill migration completes

-- Test users with Argon2 hashes
INSERT INTO password (email, password_hash, super_admin, login_type) VALUES 
('admin@lab.local', '$argon2id$v=19$m=19456,t=2,p=1$saltsaltsaltsalt$hashhashhashhashhashhashhashhas', true, 'password'),
('developer@lab.local', '$argon2id$v=19$m=19456,t=2,p=1$devsaltdevsalt00$devhashdevhashdevhashdevhashdev', false, 'password'),
('operator@lab.local', '$argon2id$v=19$m=19456,t=2,p=1$opsaltopsaltops0$ophashophashophashophashophash', false, 'password')
ON CONFLICT (email) DO NOTHING;

-- Custom secrets in global_settings
INSERT INTO global_settings (name, value) VALUES 
('custom_api_key', '"sk-live-TESTKEY1234567890ABCDEFGHIJ"'),
('smtp_password', '"SuperSecretSMTPPass123!"'),
('webhook_secret', '"whsec_testwebhooksecret1234567890"')
ON CONFLICT (name) DO NOTHING;

-- API tokens (32 chars for detection)
INSERT INTO token (token, email, label, expiration) VALUES 
('AdminToken1234567890ABCDEFGHIJK', 'admin@lab.local', 'admin_api_token', NOW() + INTERVAL '365 days'),
('DevToken567890ABCDEFGHIJKLMNOPQ', 'developer@lab.local', 'dev_ci_token', NOW() + INTERVAL '90 days'),
('OpsToken890ABCDEFGHIJKLMNOPQRST', 'operator@lab.local', 'ops_monitoring', NOW() + INTERVAL '30 days')
ON CONFLICT (token) DO NOTHING;

-- Resources with credentials
INSERT INTO resource (workspace_id, path, value, resource_type, description) VALUES 
('admins', 'f/db/postgres_prod', '{"host":"db.prod.internal","port":5432,"user":"app_user","password":"ProdDBPassword123!"}', 'postgresql', 'Production database'),
('admins', 'f/cloud/aws_keys', '{"access_key_id":"AKIAIOSFODNN7EXAMPLE","secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}', 'aws', 'AWS credentials'),
('admins', 'f/api/stripe_keys', '{"publishable_key":"pk_live_abc123","secret_key":"sk_live_xyz789secretkey"}', 'stripe', 'Stripe API keys'),
('admins', 'f/smtp/mailserver', '{"host":"smtp.company.com","port":587,"username":"noreply@company.com","password":"SMTPSecretPass!"}', 'smtp', 'Email server')
ON CONFLICT (workspace_id, path) DO NOTHING;

-- Force write to disk
CHECKPOINT;
