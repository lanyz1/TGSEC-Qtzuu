# GitLab Gitea HTTPS import SSRF (UrlBlocker pin drop)

Image: gitlab/gitlab-ce:19.4.1-ce.0
Oracle: GITLAB-GITEA-IMPORT-SSRF-WITNESS in GET /import/gitea/status.json

allow_local_requests_from_web_hooks_and_services stays off.

HTTPS `client_options` uses `provider_url` (hostname) instead of the IP-pinned
`verified_url`. HTTP uses the pin (negative). Direct https://127.0.0.1 is
blocked by UrlBlocker (negative). Lab is DNS rebind of gitea.lab: UrlBlocker
and Octokit UrlValidation A-lookups return 1.1.1.1; Faraday connect lookups
return 127.0.0.1 to the catcher on GitLab loopback :443 (`pairs` mode, because
Octokit also GETs /rate_limit before /user/repos).

Root password cannot contain the username substring `root` (GitLab WeakPasswords). CA lives in writable `trusted-certs/` because reconfigure moves/links those files (a read-only file bind-mount is EROFS).

Replay: ./run.sh
