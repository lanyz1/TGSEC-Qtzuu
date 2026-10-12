<?php
declare(strict_types=1);

header("Content-Type: text/plain; charset=utf-8");

$witness = "OLS-DUP-COOKIE-LITESPEED-ROLE-WITNESS";
$http_cookie = isset($_SERVER["HTTP_COOKIE"]) ? (string) $_SERVER["HTTP_COOKIE"] : "";
$role = isset($_COOKIE["litespeed_role"]) ? (string) $_COOKIE["litespeed_role"] : "";

echo "HTTP_COOKIE=" . $http_cookie . "\n";
if ($role !== "") {
    echo "litespeed_role=" . $role . "\n";
}
if (strpos($http_cookie, $witness) !== false || strpos($role, $witness) !== false) {
    echo $witness . "\n";
}
