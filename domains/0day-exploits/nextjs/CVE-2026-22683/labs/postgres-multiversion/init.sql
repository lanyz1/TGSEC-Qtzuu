-- Test database with various PostgreSQL types

-- Enable extensions for older PostgreSQL versions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table with different text types
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    password_hash TEXT,
    bio TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO users (username, email, password_hash, bio) VALUES
('admin', 'admin@example.com', '$argon2id$v=19$m=65536,t=3,p=4$abc123$hashedpassword', 'System administrator'),
('alice', 'alice@example.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.xQgKj9F', 'Security researcher'),
('bob', 'bob@corp.local', '$argon2id$v=19$m=65536,t=3,p=4$xyz789$anotherhash', 'Developer'),
('charlie', 'charlie@test.io', '$2a$10$N9qo8uLOickgx2ZMRZoMye', 'QA Engineer');

-- Secrets table with JSONB
CREATE TABLE secrets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    value JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO secrets (name, value) VALUES
('jwt_config', '{"secret": "super-secret-jwt-key-12345", "algorithm": "HS256", "expiry": 3600}'),
('smtp_config', '{"host": "smtp.example.com", "port": 587, "username": "mailer@example.com", "password": "smtp_password_123"}'),
('aws_credentials', '{"access_key": "AKIAIOSFODNN7EXAMPLE", "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "region": "us-east-1"}'),
('database_url', '{"url": "postgresql://admin:db_secret_pass@db.internal:5432/production"}'),
('oauth_github', '{"client_id": "Iv1.abc123def456", "client_secret": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}');

-- API tokens table
CREATE TABLE api_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(64) NOT NULL,
    scope TEXT[],
    expires_at TIMESTAMP
);

INSERT INTO api_tokens (user_id, token, scope, expires_at) VALUES
(1, 'tok_admin_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', ARRAY['admin', 'read', 'write'], '2030-01-01'),
(2, 'tok_alice_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy', ARRAY['read', 'write'], '2025-06-01'),
(3, 'tok_bob_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', ARRAY['read'], '2025-12-31');

-- Numeric types table
CREATE TABLE metrics (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50),
    value_int INTEGER,
    value_bigint BIGINT,
    value_float REAL,
    value_double DOUBLE PRECISION,
    value_numeric NUMERIC(10,2),
    value_bool BOOLEAN
);

INSERT INTO metrics (name, value_int, value_bigint, value_float, value_double, value_numeric, value_bool) VALUES
('cpu_usage', 75, 9223372036854775807, 3.14159, 2.718281828459045, 1234.56, true),
('memory_mb', 8192, 1099511627776, 0.5, 0.123456789012345, 9999.99, false),
('disk_io', -100, -9223372036854775808, -1.5, -999.999, -0.01, true);

-- Binary and bytea
CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255),
    content BYTEA,
    mime_type VARCHAR(100)
);

INSERT INTO files (filename, content, mime_type) VALUES
('secret.key', E'\\x48656c6c6f20576f726c6421', 'application/octet-stream'),
('config.bin', E'\\xdeadbeefcafebabe', 'application/octet-stream');

-- Date/time types
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    event_date DATE,
    event_time TIME,
    event_timestamp TIMESTAMP,
    event_timestamptz TIMESTAMPTZ,
    duration INTERVAL
);

INSERT INTO events (name, event_date, event_time, event_timestamp, event_timestamptz, duration) VALUES
('Launch', '2024-01-15', '14:30:00', '2024-01-15 14:30:00', '2024-01-15 14:30:00+00', '2 hours'),
('Meeting', '2024-06-20', '09:00:00', '2024-06-20 09:00:00', '2024-06-20 09:00:00-05', '1 day 2 hours');

-- UUID type
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id INTEGER REFERENCES users(id),
    ip_address INET,
    data JSONB
);

INSERT INTO sessions (user_id, ip_address, data) VALUES
(1, '192.168.1.100', '{"browser": "Firefox", "os": "Linux"}'),
(2, '10.0.0.50', '{"browser": "Chrome", "os": "Windows"}');

-- Array types
CREATE TABLE tags (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50),
    keywords TEXT[],
    scores INTEGER[]
);

INSERT INTO tags (name, keywords, scores) VALUES
('security', ARRAY['vuln', 'exploit', 'cve'], ARRAY[10, 20, 30]),
('dev', ARRAY['code', 'test', 'deploy', 'ci/cd'], ARRAY[5, 15, 25, 35]);

-- Composite/nested JSONB
CREATE TABLE configurations (
    id SERIAL PRIMARY KEY,
    app_name VARCHAR(50),
    config JSONB
);

INSERT INTO configurations (app_name, config) VALUES
('webapp', '{
    "database": {
        "host": "db.internal",
        "port": 5432,
        "credentials": {
            "username": "app_user",
            "password": "super_secret_db_pass"
        }
    },
    "redis": {
        "host": "redis.internal",
        "password": "redis_pass_123"
    },
    "features": ["auth", "api", "websocket"]
}'),
('worker', '{
    "queue": {
        "url": "amqp://rabbit:rabbit_pass@mq.internal:5672"
    },
    "secrets": {
        "encryption_key": "aes256-key-xxxxxxxxxxxxxxxx",
        "signing_key": "hmac-sha256-yyyyyyyyyyyyyyyy"
    }
}');

-- Check tables are populated
SELECT 'users' as table_name, count(*) as rows FROM users
UNION ALL SELECT 'secrets', count(*) FROM secrets
UNION ALL SELECT 'api_tokens', count(*) FROM api_tokens
UNION ALL SELECT 'metrics', count(*) FROM metrics
UNION ALL SELECT 'files', count(*) FROM files
UNION ALL SELECT 'events', count(*) FROM events
UNION ALL SELECT 'sessions', count(*) FROM sessions
UNION ALL SELECT 'tags', count(*) FROM tags
UNION ALL SELECT 'configurations', count(*) FROM configurations;
