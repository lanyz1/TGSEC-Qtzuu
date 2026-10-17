#!/bin/sh
set -eu

cat > /oracle/secret.xml <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>lab-oracle</title>
    <link>http://127.0.0.1/lab</link>
    <description>planted host XML</description>
    <item>
      <title>PFSENSE-RSS-FILE-REDIRECT-WITNESS</title>
      <link>http://127.0.0.1/item</link>
      <description>PFSENSE-RSS-FILE-REDIRECT-WITNESS</description>
    </item>
  </channel>
</rss>
EOF
chmod 0644 /oracle/secret.xml

php -S 127.0.0.1:19101 /lab/redirect.php >/tmp/redirect.log 2>&1 &
exec php -S 0.0.0.0:19100 -t /lab /lab/gadget.php
