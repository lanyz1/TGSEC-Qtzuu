# GitLab CE 19.4.1 - webhook SSRF via UrlBlocker 0.0.0.0/8

Image: `gitlab/gitlab-ce:19.4.1-ce.0`
Oracle: `GITLAB-WEBHOOK-0NET-SSRF-WITNESS` in hook `response_body`

`allow_local_requests_from_web_hooks_and_services` stays off.

Catcher shares the GitLab netns, binds `0.0.0.1:18080` with `IP_FREEBIND` plus
`ip route add local 0.0.0.1/32 dev lo`. Do not add `0.0.0.1` to `lo` as a
real address: `validate_localhost` unions `Socket.ip_address_list` and would
422 the hook create.

Negatives: `http://127.0.0.1:18080/` and `http://169.254.169.254/` 422.

GitLab 19.4 rejects a seed password that contains the username substring
`root` (WeakPasswords). Compose `$$` so `$` in the password is not interpolated.

Replay: `./run.sh`
