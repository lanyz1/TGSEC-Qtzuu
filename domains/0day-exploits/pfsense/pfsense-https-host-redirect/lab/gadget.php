<?php
/* pfSense CE 2.9.0-DEVELOPMENT HTTP-to-HTTPS $http_host 301 gadget. Pin 9363ac5. */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/system.inc.excerpt.php';
require __DIR__ . '/pin-src/auth.inc.excerpt.php';

const LABEL = 'PFSENSE-HTTPS-HOST-REDIRECT';
const WITNESS = 'PFSENSE-HTTPS-HOST-REDIRECT-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-HTTPS-HOST-REDIRECT-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const NGINX_CONF = '/lab/nginx.conf';
const PIN_SERVER = '/lab/pin-redirect.server.conf';
const NGINX_HOST = '127.0.0.1';
const NGINX_PORT = 8080;
const LAB_URI = '/index.php';
const GUI_SERVER_ADDR = '192.0.2.1';

ini_set('display_errors', '0');

function send_json(int $status, array $payload): void {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n";
	exit;
}

function send_text(int $status, string $body): void {
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit;
}

function reset_oracle(): void {
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
}

function witness_state(): array {
	$body = '';
	$exists = is_file(WITNESS_PATH);
	if ($exists) {
		$read = file_get_contents(WITNESS_PATH);
		$body = is_string($read) ? $read : '';
	}
	return array(
		'exists' => $exists,
		'body' => $body,
		'path' => WITNESS_PATH,
	);
}

function pin_redirect_block(): string {
	return system_generate_nginx_http_https_redirect(false, '443');
}

function write_nginx_conf(): void {
	$block = pin_redirect_block();
	if ($block === '' || !str_contains($block, 'return 301 https://$http_host')) {
		fwrite(STDERR, "pin-redirect-empty\n");
		exit(1);
	}
	file_put_contents(PIN_SERVER, $block);
	$lab_block = str_replace('listen 80;', 'listen ' . NGINX_HOST . ':' . NGINX_PORT . ';', $block);
	$lab_block = str_replace("listen [::]:80;", "# listen [::]:80; lab-ipv4-only", $lab_block);
	$conf = <<<EOD
pid /tmp/pfsense-https-host-redirect.pid;
error_log /lab/nginx-error.log warn;
worker_processes 1;
daemon on;
events {
    worker_connections 32;
}
http {
    access_log /lab/nginx-access.log;
    server_tokens off;
{$lab_block}
}

EOD;
	file_put_contents(NGINX_CONF, $conf);
}

function request_json(): array {
	$raw = file_get_contents('php://input');
	if (!is_string($raw) || $raw === '') {
		return array();
	}
	$data = json_decode($raw, true);
	return is_array($data) ? $data : array();
}

function request_case(): string {
	if (isset($_POST['case']) && is_string($_POST['case'])) {
		return $_POST['case'];
	}
	if (isset($_GET['case']) && is_string($_GET['case'])) {
		return $_GET['case'];
	}
	$body = request_json();
	if (isset($body['case']) && is_string($body['case'])) {
		return $body['case'];
	}
	return '';
}

function request_field(string $key, string $default = ''): string {
	if (isset($_POST[$key]) && is_string($_POST[$key])) {
		return $_POST[$key];
	}
	if (isset($_GET[$key]) && is_string($_GET[$key])) {
		return $_GET[$key];
	}
	$body = request_json();
	if (isset($body[$key]) && is_string($body[$key])) {
		return $body[$key];
	}
	return $default;
}

function parse_http_response(string $raw): array {
	$parts = preg_split("/\r\n\r\n/", $raw, 2);
	$header_blob = $parts[0] ?? '';
	$body = $parts[1] ?? '';
	$status = 0;
	$reason = '';
	$headers = array();
	$lines = preg_split("/\r\n/", $header_blob) ?: array();
	if (isset($lines[0]) && preg_match('/^HTTP\/\d(?:\.\d)?\s+(\d{3})\s*(.*)$/', $lines[0], $m)) {
		$status = (int) $m[1];
		$reason = trim($m[2]);
	}
	foreach (array_slice($lines, 1) as $line) {
		$idx = strpos($line, ':');
		if ($idx === false) {
			continue;
		}
		$name = strtolower(trim(substr($line, 0, $idx)));
		$headers[$name] = ltrim(substr($line, $idx + 1));
	}
	return array(
		'status' => $status,
		'reason' => $reason,
		'headers' => $headers,
		'location' => $headers['location'] ?? '',
		'body' => $body,
		'raw' => $raw,
	);
}

function nginx_get(string $host, string $uri): array {
	$fp = @fsockopen(NGINX_HOST, NGINX_PORT, $errno, $errstr, 3);
	if ($fp === false) {
		return array(
			'ok' => false,
			'error' => "nginx-connect {$errno} {$errstr}",
			'status' => 0,
			'location' => '',
			'host' => $host,
			'uri' => $uri,
		);
	}
	stream_set_timeout($fp, 3);
	$req = "GET {$uri} HTTP/1.1\r\n";
	$req .= "Host: {$host}\r\n";
	$req .= "Connection: close\r\n\r\n";
	fwrite($fp, $req);
	$raw = stream_get_contents($fp);
	fclose($fp);
	if (!is_string($raw) || $raw === '') {
		return array(
			'ok' => false,
			'error' => 'nginx-empty',
			'status' => 0,
			'location' => '',
			'host' => $host,
			'uri' => $uri,
		);
	}
	$parsed = parse_http_response($raw);
	$parsed['ok'] = true;
	$parsed['error'] = '';
	$parsed['host'] = $host;
	$parsed['uri'] = $uri;
	$parsed['php_ran'] = false;
	return $parsed;
}

function php_rebind(string $host): array {
	$_SERVER['HTTP_HOST'] = $host;
	$_SERVER['SERVER_ADDR'] = GUI_SERVER_ADDR;
	$GLOBALS['lab_error_form'] = array();
	return lab_dns_rebind_check();
}

function maybe_store_witness(string $location): void {
	if ($location !== '' && str_contains($location, WITNESS)) {
		file_put_contents(WITNESS_PATH, $location . "\n");
	}
}

function run_nginx_case(string $host, string $uri): array {
	$resp = nginx_get($host, $uri);
	$location = (string) ($resp['location'] ?? '');
	maybe_store_witness($location);
	$resp['witness'] = witness_state();
	$resp['pin_return'] = 'return 301 https://$http_host$request_uri;';
	$resp['expected'] = 'https://' . $host . $uri;
	$resp['location_matches_host'] = ($location === ('https://' . $host . $uri));
	$resp['dns_rebind_ran'] = false;
	return $resp;
}

if (PHP_SAPI === 'cli' && isset($argv[1]) && $argv[1] === '--write-nginx') {
	write_nginx_conf();
	fwrite(STDOUT, "wrote " . NGINX_CONF . "\n");
	exit(0);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	$block = pin_redirect_block();
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'unauth',
		'protocol' => config_get_path('system/webgui/protocol'),
		'redirect' => $block !== '',
		'nginx_listen' => NGINX_HOST . ':' . NGINX_PORT,
		'witness_path' => WITNESS_PATH,
		'label' => LABEL,
		'witness' => WITNESS,
	));
}

if ($path === '/source') {
	$sys = file_get_contents(__DIR__ . '/pin-src/system.inc.excerpt.php');
	$auth = file_get_contents(__DIR__ . '/pin-src/auth.inc.excerpt.php');
	$generated = is_file(PIN_SERVER) ? file_get_contents(PIN_SERVER) : '';
	if ($sys === false || $auth === false) {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $sys . "\n" . $auth . "\n" . $generated);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/run') {
	$case = request_case();
	$host = request_field('host', '');
	$uri = request_field('uri', LAB_URI);
	if ($uri === '' || $uri[0] !== '/') {
		send_json(400, array('error' => 'bad-uri'));
	}
	if ($case === 'control') {
		reset_oracle();
		if ($host === '') {
			$host = 'localhost';
		}
		send_json(200, run_nginx_case($host, $uri));
	}
	if ($case === 'trigger') {
		reset_oracle();
		if ($host === '') {
			$host = 'evil.example';
		}
		send_json(200, run_nginx_case($host, $uri));
	}
	if ($case === 'witness') {
		reset_oracle();
		if ($host === '') {
			$host = WITNESS;
		}
		send_json(200, run_nginx_case($host, $uri));
	}
	if ($case === 'php-rebind') {
		if ($host === '') {
			send_json(400, array('error' => 'missing-host'));
		}
		$rebind = php_rebind($host);
		$rebind['ok'] = true;
		$rebind['case'] = 'php-rebind';
		send_json(200, $rebind);
	}
	send_json(400, array('error' => 'bad-case', 'case' => $case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
