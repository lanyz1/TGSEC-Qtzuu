# GitHub token capability probing + archive push (2026-09 session findings)

## Fine-grained PAT limitations (durable facts)

- **Fine-grained PATs (`github_pat_...`) CANNOT create repositories.** `POST /user/repos`
  returns `Resource not accessible by personal access token` regardless of scopes shown.
  Repo creation requires a classic PAT with `repo` scope, or web-created repo.
- **`/user/repos` only lists repos the token is granted.** Empty list does NOT mean the user
  has no repos — the token may only be granted zero repos.
- **`GET /repos/{owner}/{repo}` `permissions` field can show `push:true` for a token that
  cannot actually write** when the token has Metadata read. Do not trust it; do a write probe.
- Repo contents `GET /repos/{owner}/{repo}/contents/` on an empty repo returns
  `This repository is empty.` (an error string, not a list) — read it as "repo exists, empty."

## Capability probe sequence (read-only → write probe)

```bash
TOKEN="github_pat_..."
# 1. identity
curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/user
# 2. repo exists
curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/repos/{owner}/{repo}
# 3. read access
curl -s -H "Authorization: Bearer $TOKEN" https://api.github.com/repos/{owner}/{repo}/contents/
# 4. WRITE probe (harmless single file; remove after)
curl -s -X PUT -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/{owner}/{repo}/contents/probe.md" \
  -d '{"message":"probe","content":"cHJvYmU="}'
# success → `content` in response; denied → `Resource not accessible by personal access token`
```

## Push recipe (after write permission confirmed)

```bash
cd /root/security-suite   # fully assembled copy (cp -rL, NO symlinks)
git init
git config user.email "you@x" && git config user.name "you"
git add -A && git commit -m "init"
git push --set-upstream https://$TOKEN@github.com/{owner}/{repo}.git main
```

Never embed a symlink tree in git — `cp -rL` dereferences first.

## User context (this operator)

GitHub user `lanyz1`; repo of record: `Qtzuu-TGSEC-` (public, empty, default branch `main`).
User provided a fine-grained PAT that lacked Contents:Write — fix path: re-issue token with

1. Fine-grained: Repository permissions → Contents → **Read and write** (choose All
   repositories when creating), or
2. Classic token with `repo` scope.
