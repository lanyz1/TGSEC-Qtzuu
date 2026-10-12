# GitLab CE 19.4.1 - Gitaly fetch omits resolved_address

Pin `gitlab/gitlab-ce:19.4.1-ce.0`. `allow_local_requests` off.

GitLab 19.4 rejects seed password `CveLabRoot9!` because it contains username `root` (weak-password substring). Seed uses a 64-char pad of that string so the check is skipped. PAT mint does not need the login password.

GitHub Enterprise import (`POST /api/v4/import/github`) skips `Projects::ImportService#get_resolved_address` because `ParallelImporter.imports_repository?` is true. `RepositoryImporter#fetch_as_mirror` leaves `resolved_address` empty.

Lab harness:

- DNS `ghe.lab` on `172.30.2.2`: A=`1.1.1.1` until catcher arms rebind, then `127.0.0.1`, TTL 0.
- Catcher shares the GitLab netns, listens on `:18080` (GHE JSON + `git http-backend`).
- iptables OUTPUT REDIRECT `1.1.1.1:18080` -> `:18080` so Faraday can reach the stub while UrlBlocker still sees a public A.
- After the worker `GET /api/v3/repos/org/repo`, catcher flips DNS and drops the redirect. Gitaly git must re-resolve to loopback.

Oracle: imported `WITNESS` blob and/or git-upload-pack on loopback after the flip.

Negative: `github_hostname=http://127.0.0.1:18080` is UrlBlocker-blocked.
