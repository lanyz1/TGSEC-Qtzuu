# GitHub Dorks
A collection of GitHub search dorks for authorized reconnaissance, source-code research, configuration discovery, and identification of potentially exposed information.

Replace {TARGET} with the authorized target, organization, domain, project name, or other relevant search term before using a query.

---

## 1. General Presence
"{TARGET}"
"{TARGET}" in:description
"{TARGET}" in:readme
org:{TARGET}
"{TARGET}" language:Go
"{TARGET}" language:Python
"{TARGET}" language:JavaScript
"{TARGET}" language:TypeScript
"{TARGET}" language:Rust
"{TARGET}" filename:Dockerfile
"{TARGET}" filename:docker-compose.yml
"{TARGET}" filename:requirements.txt
"{TARGET}" filename:package.json

---

## 2. Secrets & Tokens
"{TARGET}" "api_key"
"{TARGET}" "apikey"
"{TARGET}" "api-token"
"{TARGET}" "x-api-key"
"{TARGET}" "access_token"
"{TARGET}" "auth_token"
"{TARGET}" "secret_token"
"{TARGET}" "client_secret"
"{TARGET}" "clientSecret"
"{TARGET}" "consumer_secret"
"{TARGET}" "refresh_token"
"{TARGET}" "slack_token"
"{TARGET}" "bot_token"
"{TARGET}" "bearer"
"{TARGET}" "Authorization: Bearer"
"{TARGET}" "Authorization: Basic"
"{TARGET}" "personal_access_token"
"{TARGET}" "PAT"
"{TARGET}" "auth='"
"{TARGET}" "auth=\""
"{TARGET}" "jwt"
"{TARGET}" "jwtSecret"
"{TARGET}" "token_secret"
"{TARGET}" "secret_key"
"{TARGET}" "SECRET_KEY"
"{TARGET}" "SESSION_SECRET"
"{TARGET}" "SIGNING_KEY"
"{TARGET}" "smtp_password"
"{TARGET}" "mail_password"
"{TARGET}" "sendgrid_api_key"
"{TARGET}" "STRIPE_SECRET_KEY"
"{TARGET}" "GH_TOKEN"

---

## 3. Cloud Credentials
"{TARGET}" "AWS_ACCESS_KEY_ID"
"{TARGET}" "AWS_SECRET_ACCESS_KEY"
"{TARGET}" "aws_access_key_id"
"{TARGET}" "aws_secret_access_key"
"{TARGET}" "AWS_SESSION_TOKEN"
"{TARGET}" "google_api_key"
"{TARGET}" "GOOGLE_MAPS_API_KEY"
"{TARGET}" "GCLOUD_KEYFILE_JSON"
"{TARGET}" "GCLOUD_PROJECT"
"{TARGET}" "GOOGLE_CLOUD_KEYFILE_JSON"
"{TARGET}" "firebase_api_key"
"{TARGET}" "FIREBASE_CONFIG"
"{TARGET}" "AZURE_STORAGE_KEY"
"{TARGET}" "AZURE_CONNECTION_STRING"
"{TARGET}" "az storage account-key"
"{TARGET}" "DO_API_TOKEN"
"{TARGET}" "digitalocean_token"
"{TARGET}" "heroku_api_key"
"{TARGET}" "HEROKU_API_KEY"
"{TARGET}" "linode_token"
"{TARGET}" "SENTRY_DSN"
"{TARGET}" "S3_BUCKET"
"{TARGET}" "s3.amazonaws.com"

---

## 4. Database Credentials
"{TARGET}" "postgres"
"{TARGET}" "POSTGRES_PASSWORD"
"{TARGET}" "PGPASSWORD"
"{TARGET}" "DATABASE_URL"
"{TARGET}" "jdbc:postgresql://"
"{TARGET}" "jdbc:mysql://"
"{TARGET}" "mysql_password"
"{TARGET}" "mongo_uri"
"{TARGET}" "mongodb+srv://"
"{TARGET}" "MONGO_INITDB_ROOT_PASSWORD"
"{TARGET}" "REDIS_URL"
"{TARGET}" "REDIS_PASSWORD"
"{TARGET}" "sqlalchemy.url"
"{TARGET}" "db_password"
"{TARGET}" "dbUser"
"{TARGET}" "dbPass"
"{TARGET}" "PGUSER"
"{TARGET}" "PGHOST"
"{TARGET}" "PGSSLMODE"
"{TARGET}" "PGDATABASE"

---

## 5. Configuration Files
"{TARGET}" ext:env
"{TARGET}" ext:yml
"{TARGET}" ext:yaml
"{TARGET}" ext:json
"{TARGET}" ext:ini
"{TARGET}" ext:toml
"{TARGET}" ext:conf
"{TARGET}" filename:.npmrc
"{TARGET}" filename:.pypirc
"{TARGET}" filename:pip.conf
"{TARGET}" filename:.rubygems
"{TARGET}" filename:gradle.properties
"{TARGET}" filename:docker-compose.yml
"{TARGET}" filename:Dockerfile
"{TARGET}" filename:settings.py
"{TARGET}" filename:application.properties
"{TARGET}" ".well-known/security.txt"

---

## 6. Source Code & Logs
"{TARGET}" ext:log
"{TARGET}" ext:sql
"{TARGET}" ext:bak
"{TARGET}" ext:old
"{TARGET}" ext:swp
"{TARGET}" ext:orig
"{TARGET}" "stack trace"
"{TARGET}" "Exception in thread"
"{TARGET}" "Traceback (most recent call last)"
"{TARGET}" "Error establishing a database connection"
"{TARGET}" "Warning: mysqli"
"{TARGET}" "docker logs"
"{TARGET}" "DEBUG = True"
"{TARGET}" "NODE_ENV=development"
"{TARGET}" "process.env"
"{TARGET}" "console.log("
"{TARGET}" "print("
"{TARGET}" "system.out.println"
"{TARGET}" "SELECT * FROM"
"{TARGET}" "INSERT INTO"
"{TARGET}" "DROP TABLE"
"{TARGET}" "base64,"

---

## 7. Advanced & Misc
"{TARGET}" "BEGIN RSA PRIVATE KEY"
"{TARGET}" "BEGIN OPENSSH PRIVATE KEY"
"{TARGET}" "BEGIN PGP PRIVATE KEY BLOCK"
"{TARGET}" "ssh-rsa AAAA"
"{TARGET}" "-----BEGIN CERTIFICATE-----"
"{TARGET}" ".pem\""
"{TARGET}" "-----BEGIN EC PRIVATE KEY-----"
"{TARGET}" "-----BEGIN DSA PRIVATE KEY-----"
"{TARGET}" "github_token"
"{TARGET}" "gitlab_token"
"{TARGET}" "circleci"
"{TARGET}" "CI_JOB_TOKEN"
"{TARGET}" "pipelines"
"{TARGET}" "artifactUrl"
"{TARGET}" "xoxb-"
"{TARGET}" "xoxp-"
"{TARGET}" "glpat-"
"{TARGET}" "sk_live_"
"{TARGET}" "sq0atp-"
"{TARGET}" "sg."
"{TARGET}" "ssm://"
"{TARGET}" "firebaseio.com"
"{TARGET}" "supabase_url"
"{TARGET}" "supabase_key"

---

## Usage
1. Replace {TARGET} with the authorized target or search term.
2. Run queries appropriate to the scope of the assessment.
3. Review results manually and verify their context.
4. Do not use or test exposed credentials unless explicitly authorized.
5. Do not access systems outside the defined scope.
6. Avoid copying or publishing sensitive values.
7. Report confirmed findings through the appropriate responsible-disclosure channel.

---

## Notes
These queries are intended for reconnaissance and security research on authorized targets.
A search result does not automatically represent a vulnerability. Findings should be validated carefully, with emphasis on scope, ownership, exposure, and actual security impact.