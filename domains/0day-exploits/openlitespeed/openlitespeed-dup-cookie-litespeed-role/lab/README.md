# OpenLiteSpeed duplicate Cookie `litespeed_role` leftover

**Reach:** Remote
**Class:** Privilege leftover

HTTP/1.1 on OpenLiteSpeed 1.9.3. A single `Cookie: litespeed_role=` is still 403
(1.8.2.1). Duplicate `Cookie` is not 400; the second line skips the scan and
lsphp still receives `HTTP_COOKIE`. Oracle is `www/cookie.php`. No WordPress.

Loopback `127.0.0.1:18750`. Replay: `./run.sh`.
