<?php
/* pfSense CE 2.9.0-DEVELOPMENT DynDNS cache-path gadget. Pin 9363ac5. */

const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const WITNESS = 'PFSENSE-DYNDNS-CACHE-PATH-WITNESS';
const PRIVILEGE = 'page-services-dynamicdnsclient';
const CONF_PATH = '/conf';
const ORACLE_DIR = '/oracle';
const DNS_IF = 'wan';
const DNS_ID = '0';
const DNS_IP = '203.0.113.10';
const CONTROL_HOST = 'example.com';
const TRIGGER_HOST = '../../../oracle/PFSENSE-DYNDNS-CACHE-PATH-WITNESS';

ini_set('display_errors', '0');
error_reporting(E_ALL);

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/dyndns.class.excerpt.php';
require __DIR__ . '/pin-src/services_dyndns_edit.php.excerpt.php';

function send_json($status, $payload) {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	exit(0);
}

function send_text($status, $body) {
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit(0);
}

function request_json() {
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

function request_field($name) {
	if (isset($_POST[$name]) && is_string($_POST[$name])) {
		return $_POST[$name];
	}
	if (isset($_GET[$name]) && is_string($_GET[$name])) {
		return $_GET[$name];
	}
	$body = request_json();
	if (isset($body[$name]) && is_string($body[$name])) {
		return $body[$name];
	}
	return '';
}

function lab_rm_tree($path) {
	if (is_link($path) || is_file($path)) {
		unlink($path);
		return;
	}
	if (!is_dir($path)) {
		return;
	}
	$entries = scandir($path);
	if ($entries === false) {
		return;
	}
	foreach ($entries as $entry) {
		if ($entry === '.' || $entry === '..') {
			continue;
		}
		lab_rm_tree($path . '/' . $entry);
	}
	rmdir($path);
}

function lab_ensure_dir($path) {
	if (is_dir($path)) {
		return true;
	}
	return mkdir($path, 0755, true) || is_dir($path);
}

function lab_resolve_path($path) {
	$absolute = str_starts_with($path, '/');
	$parts = explode('/', $path);
	$out = array();
	foreach ($parts as $part) {
		if ($part === '' || $part === '.') {
			continue;
		}
		if ($part === '..') {
			array_pop($out);
			continue;
		}
		$out[] = $part;
	}
	$joined = implode('/', $out);
	if ($absolute) {
		return '/' . $joined;
	}
	return $joined;
}

function lab_under_conf($resolved) {
	$root = rtrim(CONF_PATH, '/');
	if ($resolved === $root) {
		return true;
	}
	return str_starts_with($resolved, $root . '/');
}

function reset_lab() {
	global $g;
	$GLOBALS['lab_logs'] = array();
	$GLOBALS['lab_notify'] = array();
	$g['conf_path'] = CONF_PATH;
	$g['varetc_path'] = '/lab/var/etc';
	lab_ensure_dir(CONF_PATH);
	lab_ensure_dir(ORACLE_DIR);
	lab_ensure_dir('/lab/var/etc');
	$conf_entries = scandir(CONF_PATH);
	if ($conf_entries !== false) {
		foreach ($conf_entries as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			if (str_starts_with($entry, 'dyndns_')) {
				lab_rm_tree(CONF_PATH . '/' . $entry);
			}
		}
	}
	$oracle_entries = scandir(ORACLE_DIR);
	if ($oracle_entries !== false) {
		foreach ($oracle_entries as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			lab_rm_tree(ORACLE_DIR . '/' . $entry);
		}
	}
}

function file_state($path) {
	$exists = is_file($path);
	$body = '';
	if ($exists) {
		$read = file_get_contents($path);
		$body = ($read === false) ? '' : $read;
	}
	return array(
		'path' => $path,
		'exists' => $exists,
		'body' => $body,
		'dirname' => dirname($path),
		'basename' => basename($path),
	);
}

function ip_epoch_body($body) {
	return is_string($body) && preg_match('/^' . preg_quote(DNS_IP, '/') . '\|[0-9]+$/', $body) === 1;
}

function run_cache($case, $type, $host) {
	reset_lab();
	$validation = dyndns_edit_check_host($type, $host);
	$dns = new updatedns(
		$type,
		$host,
		'',
		'lab',
		'lab',
		'OFF',
		false,
		'',
		DNS_IF,
		'',
		'',
		'',
		'http://127.0.0.1/update',
		false,
		'',
		'',
		'',
		DNS_IF,
		'',
		DNS_ID,
		false
	);
	$constructed = $dns->_cacheFile;
	$quoted = escapeshellarg($host);
	$resolved = lab_resolve_path($constructed);
	$prefix = CONF_PATH . '/dyndns_' . DNS_IF . $type . "'";
	$prefix_mkdir = false;
	if ($case === 'trigger' && str_contains($host, '/')) {
		$prefix_mkdir = lab_ensure_dir($prefix);
	}
	$committed = $dns->lab_commit_ipv4(DNS_IP);
	$constructed_state = file_state($constructed);
	$resolved_state = file_state($resolved);
	$body = $resolved_state['exists'] ? $resolved_state['body'] : $constructed_state['body'];
	$write_dir = $resolved_state['exists'] ? $resolved_state['dirname'] : $constructed_state['dirname'];
	$under = lab_under_conf($resolved);
	$outside = $resolved_state['exists'] && !lab_under_conf($resolved);
	return array(
		'ok' => true,
		'case' => $case,
		'type' => $type,
		'host' => $host,
		'slash_in_host' => str_contains($host, '/'),
		'quoted_fqdn' => $quoted,
		'constructed' => $constructed,
		'resolved' => $resolved,
		'write_dir' => $write_dir,
		'conf_path' => CONF_PATH,
		'prefix_dir' => $prefix,
		'prefix_mkdir' => $prefix_mkdir,
		'prefix_is_dir' => is_dir($prefix),
		'successful_update' => (bool) $committed,
		'status' => $dns->status,
		'ip' => DNS_IP,
		'body' => $body,
		'ip_epoch' => ip_epoch_body($body),
		'constructed_exists' => $constructed_state['exists'],
		'resolved_exists' => $resolved_state['exists'],
		'under_conf' => $under && $constructed_state['exists'],
		'outside_conf' => $outside,
		'witness_in_path' => str_contains($resolved, WITNESS),
		'witness_in_body' => str_contains($body, WITNESS),
		'validation' => $validation,
		'notify' => $GLOBALS['lab_notify'],
		'logs' => array_map(
			static function ($row) {
				return $row['message'];
			},
			$GLOBALS['lab_logs']
		),
	);
}

function oracle_state() {
	$files = array();
	foreach (array(CONF_PATH, ORACLE_DIR) as $root) {
		if (!is_dir($root)) {
			continue;
		}
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
		);
		foreach ($iterator as $info) {
			if (!$info->isFile()) {
				continue;
			}
			$path = $info->getPathname();
			$files[] = file_state($path);
		}
	}
	$hit = null;
	foreach ($files as $row) {
		if (str_contains($row['path'], WITNESS) && ip_epoch_body($row['body'])) {
			$hit = $row;
			break;
		}
	}
	return array(
		'files' => $files,
		'witness_file' => $hit,
		'witness_in_filename' => is_array($hit),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping' || $path === '/health.php') {
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => PRIVILEGE,
		'conf_path' => CONF_PATH,
		'oracle_dir' => ORACLE_DIR,
		'witness' => WITNESS,
		'control_host' => CONTROL_HOST,
		'trigger_host' => TRIGGER_HOST,
		'ip' => DNS_IP,
		'exec' => function_exists('exec'),
	));
}

if ($path === '/source') {
	$class_src = file_get_contents(__DIR__ . '/pin-src/dyndns.class.excerpt.php');
	$gui_src = file_get_contents(__DIR__ . '/pin-src/services_dyndns_edit.php.excerpt.php');
	$util_src = file_get_contents(__DIR__ . '/pin-src/util.inc.excerpt.php');
	if ($class_src === false || $gui_src === false || $util_src === false) {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $class_src . "\n" . $gui_src . "\n" . $util_src);
}

if ($path === '/pin/class') {
	$src = file_get_contents(__DIR__ . '/pin-src/dyndns.class.excerpt.php');
	if ($src === false) {
		send_text(500, 'pin-class-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/pin/gui') {
	$src = file_get_contents(__DIR__ . '/pin-src/services_dyndns_edit.php.excerpt.php');
	if ($src === false) {
		send_text(500, 'pin-gui-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, oracle_state());
}

if ($path === '/run') {
	$case = request_field('case');
	$host = request_field('host');
	$type = request_field('type');
	if ($type === '') {
		$type = 'custom';
	}
	if ($case === 'control') {
		if ($host === '') {
			$host = CONTROL_HOST;
		}
		send_json(200, run_cache($case, $type, $host));
	}
	if ($case === 'trigger') {
		if ($host === '') {
			$host = TRIGGER_HOST;
		}
		send_json(200, run_cache($case, $type, $host));
	}
	if ($case === 'dyndns-reject') {
		if ($host === '') {
			$host = TRIGGER_HOST;
		}
		reset_lab();
		$validation = dyndns_edit_check_host('dyndns', $host);
		send_json(200, array(
			'ok' => true,
			'case' => $case,
			'type' => 'dyndns',
			'host' => $host,
			'validation' => $validation,
		));
	}
	send_json(400, array('error' => 'bad-case', 'case' => $case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
