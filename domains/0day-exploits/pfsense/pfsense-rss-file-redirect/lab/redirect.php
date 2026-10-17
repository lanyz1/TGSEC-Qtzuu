<?php
/* Tiny in-container HTTP listener. 3xx Location is the leftover, not the feed body. */
http_response_code(302);
header('Location: file:///oracle/secret.xml');
header('Content-Type: text/plain; charset=utf-8');
header('Connection: close');
echo "redirect\n";
exit(0);
