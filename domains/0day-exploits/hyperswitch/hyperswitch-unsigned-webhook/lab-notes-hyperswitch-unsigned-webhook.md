# Lab notes — hyperswitch-unsigned-webhook

## 1. The CVE, in one sitting

hyperswitch-unsigned-webhook hits **Hyperswitch 2026.09.21.0 (Juspay)**. Lab kind: `docker`.

Unpublished Hyperswitch source finding: unsigned Worldpayxml (and BitPay/Shift4) inbound webhooks are treated as verified and consume a payment as Charged without PSync. Worldpayxml verify_webhook_source returns Ok(true). Default algorithm is NoAlgorithm.

The mapped entry is `POST /webhooks/{merchant_id}/worldpayxml`. What the advisory *names* and what the code *does* are not always the same:

Unauthenticated unpublished Hyperswitch #1 CWE-345 2026.09.21.0. Needs merchant_id in URL and connector orderCode. Witness: GET /payments/{id} status succeeded. BitPay/Shift4 NoAlgorithm same class. Not eval. Not a reverse shell. Disclose security@juspay.in, not a public GitHub issue.

Witness we wanted: GET /payments/{id} status=succeeded after unsigned SETTLED webhook; attempt Charged

---

## 2. The lab

Isolated, loopback-only (`127.0.0.1`). After disclosure, the same files ship in the advisory repo under `lab/` so others can stand this up, confirm the witness, then patch their own systems.

### Dockerfile(s)

Copy these as-is. If Compose mounts a local product tree, put the vulnerable version next to the YAML.

### `lab/Dockerfile`

```dockerfile
# Loopback lab image pin for hyperswitch-unsigned-webhook. Full stack: docker-compose.yml
FROM docker.io/debian:trixie-slim
```

### docker-compose.yml

```yaml
# Loopback Hyperswitch lab for unpublished #1 (unsigned Worldpayxml webhook → Charged).
# Config/migrations from client-reviews/hyperswitch/src tag 2026.09.21.0.

name: hyperswitch-unsigned-webhook

networks:
  router_net:

volumes:
  pg_data:

services:
  pg:
    image: docker.io/postgres:16
    networks: [router_net]
    volumes:
      - pg_data:/var/lib/postgresql
    environment:
      POSTGRES_USER: db_user
      POSTGRES_PASSWORD: db_pass
      POSTGRES_DB: hyperswitch_db
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d hyperswitch_db -U db_user"]
      interval: 5s
      retries: 20
      start_period: 10s
      timeout: 5s

  redis-standalone:
    image: docker.io/redis:7
    networks: [router_net]
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep '^PONG$'"]
      interval: 5s
      retries: 10
      start_period: 5s
      timeout: 5s

  migration_runner:
    image: docker.io/debian:trixie-slim
    command: >
      bash -c "
      apt-get update && apt-get install -y curl xz-utils &&
      curl --proto '=https' --tlsv1.2 -LsSf https://github.com/diesel-rs/diesel/releases/download/v2.3.5/diesel_cli-installer.sh | bash &&
      export PATH=\"$$PATH:$$HOME/.cargo/bin\" &&
      diesel migration run --database-url \"$$DATABASE_URL\" --migration-dir /migrations"
    working_dir: /tmp
    networks: [router_net]
    volumes:
      - ../../client-reviews/hyperswitch/src/migrations:/migrations:ro
    environment:
      DATABASE_URL: postgresql://db_user:db_pass@pg:5432/hyperswitch_db
    depends_on:
      pg:
        condition: service_healthy

  superposition:
    image: ghcr.io/juspay/superposition-demo:0.113.0
    networks: [router_net]
    environment:
      API_HOSTNAME: http://superposition:8080
      REDIS_URL: redis://redis-standalone:6379
    depends_on:
      redis-standalone:
        condition: service_healthy

  superposition-init:
    image: alpine:latest
    depends_on:
      superposition:
        condition: service_started
    networks: [router_net]
    volumes:
      - ../../client-reviews/hyperswitch/src/config/superposition_seed.toml:/seed.toml:ro
      - ../../client-reviews/hyperswitch/src/scripts/seed_superposition.sh:/seed_superposition.sh:ro
    environment:
      SUPERPOSITION_URL: http://superposition:8080
      SEED_FILE: /seed.toml
      WORKSPACE_ID: dev
      ORG_ID: localorg
    command: sh -c "apk add --no-cache bash curl jq yq && bash /seed_superposition.sh"
    restart: "no"

  hyperswitch-server:
    image: docker.juspay.io/juspaydotin/hyperswitch-router:standalone
    command: /local/bin/router -f /local/config/docker_compose.toml
    ports:
      - "127.0.0.1:18082:8080"
    networks: [router_net]
    volumes:
      - ../../client-reviews/hyperswitch/src/config:/local/config:ro
      - ./files:/local/bin/files
    depends_on:
      pg:
        condition: service_healthy
      redis-standalone:
        condition: service_healthy
      migration_runner:
        condition: service_completed_successfully
      superposition:
        condition: service_started
    healthcheck:
      test: curl --fail http://localhost:8080/health || exit 1
      interval: 5s
      retries: 20
      start_period: 10s
      timeout: 5s
```



### Bring-up (typical)

```bash
cd lab
docker compose up --force-recreate
```

1. Bind the plugin or product tree at the vulnerable version (here: `2026.09.21.0`).
2. Wait until HTTP on the published loopback port answers.
3. If WordPress: `wp core install` on loopback, then activate the plugin.
4. Apply lab fixtures so the sink is actually reachable.

### Fixtures

- Stock install of the vulnerable version; extra fixtures only if the sink needs them.

### Preconditions the sink needed

- Hyperswitch v1 router
- Merchant with worldpayxml MCA
- Payment attempt with connector_transaction_id matching orderCode
- Intent past confirmation (requires_capture / processing)

---

## 3. Steps we took, and the holes we fell in

The first client was almost always too polite. It used the names in the CVE write-up (or the source defaults) instead of the names the running process actually reads. That produces a convincing **200** with a theme page — tens of kilobytes of HTML — and zero witness.

What "success" is *not*:

- eval/base64/system payload
- reverse shell
- unverified webhooks only PSync
- payment stays requires_confirmation / requires_capture

What actually moved the needle:

1. Treat the **on-disk product** as the spec. Function names in the advisory are PHP methods, not HTTP `action=` unless a hook says so.
2. Discover any nonce / form id / router key the way an unauthenticated visitor would (public REST, a rendered form, a marker in a fixture page). Yesterday's hard-coded names miss when the running process mints them.
3. Send the method the handler is registered for. A GET where the schema only allows POST (or the reverse) is a 400, not a sink.
4. Keep the witness **in the body** (or `debug.log` if display is off). A unique string proving the sink ran is the proof; generic success JSON is not.
5. Side paths can abort the sink. A mailer fatal before meta is stored, a duplicate unique key, or a serialized payload whose class-length prefix does not match the class name will look like a valid form response while the object never instantiated.

Last operator run (trimmed):

```
SUCCESS Hyperswitch unsigned Worldpayxml webhook Charged
IOC payment_id=pay_BalhxoQdS8mrL4JmsHgu status_before=requires_confirmation
IOC webhook status=200 unsigned lastEvent=SETTLED
IOC poll status=succeeded
```

When it finally landed, the response was small JSON — not a WordPress homepage. That size jump (eighty kilobytes of theme → a few hundred bytes of JSON) is the tell that the router matched.
