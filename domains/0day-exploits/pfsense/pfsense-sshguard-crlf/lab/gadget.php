<?php
/* pfSense CE 2.9.0-DEVELOPMENT sshguard.conf CRLF BACKEND gadget. Pin 9363ac5. */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/syslog.inc.excerpt.php';
require __DIR__ . '/pin-src/system_advanced_admin.inc.excerpt.php';

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));
ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-SSHGUARD-CRLF-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-SSHGUARD-CRLF-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const CONF_PATH = '/usr/local/etc/sshguard.conf';
const DEFAULT_BACKEND = '/usr/local/libexec/sshg-fw-pf';
const PRIVILEGE = 'page-system-advanced-admin';

function reset_oracle() {
	$GLOBALS['lab_config'] = array();
	$GLOBALS['lab_mwexec'] = array();
	$GLOBALS['lab_backend'] = array(
		'output' => '',
		'exit' => null,
		'path' => null,
	);
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_numericint_calls'] = array();
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
	if (is_file(CONF_PATH)) {
		unlink(CONF_PATH);
	}
	if (is_file('/usr/local/etc/sshguard.whitelist')) {
		unlink('/usr/local/etc/sshguard.whitelist');
	}
}

function witness_state() {
	$exists = is_file(WITNESS_PATH);
	$body = '';
	if ($exists) {
		$read = file_get_contents(WITNESS_PATH);
		$body = ($read === false) ? '' : $read;
	}
	return array(
		'exists' => $exists,
		'body' => $body,
		'path' => WITNESS_PATH,
	);
}

function conf_body() {
	if (!is_file(CONF_PATH)) {
		return '';
	}
	$read = file_get_contents(CONF_PATH);
	return ($read === false) ? '' : $read;
}

function backend_lines($body) {
	$hits = array();
	foreach (preg_split("/\r\n|\n|\r/", $body) as $line) {
		if ($line === '') {
			continue;
		}
		if (str_starts_with($line, 'BACKEND=')) {
			$hits[] = $line;
		}
	}
	return $hits;
}

function send_json($status, $payload) {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
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

function request_field($name, $default = '') {
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
	return $default;
}

function numericint_applied($threshold) {
	foreach ($GLOBALS['lab_numericint_calls'] as $arg) {
		if ($arg === $threshold) {
			return true;
		}
	}
	return false;
}

function run_save($threshold) {
	reset_oracle();
	$would_reject = !is_numericint($threshold);
	$GLOBALS['lab_numericint_calls'] = array();
	$post = array(
		'sshguard_threshold' => $threshold,
		'sshguard_blocktime' => '',
		'sshguard_detection_time' => '',
	);
	$saved = save_sshguard_from_post($post, false);
	$body = conf_body();
	$backends = backend_lines($body);
	$applied = numericint_applied($threshold);
	if ($applied) {
		$would_reject = true;
	}
	return array(
		'ok' => true,
		'threshold_posted' => $threshold,
		'threshold_stored' => config_get_path('system/sshguard_threshold', ''),
		'input_errors' => $saved['input_errors'],
		'restart_sshguard' => $saved['restart_sshguard'],
		'write_config' => $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'mwexec' => $GLOBALS['lab_mwexec'],
		'conf_path' => CONF_PATH,
		'conf_body' => $body,
		'backend_lines' => $backends,
		'backend_count' => count($backends),
		'backend' => $GLOBALS['lab_backend'],
		'numericint_applied' => $applied,
		'numericint_would_reject' => $would_reject,
		'default_backend' => DEFAULT_BACKEND,
		'privilege' => PRIVILEGE,
		'warn_root' => false,
		'witness' => witness_state(),
	);
}

function pin_source() {
	$parts = array();
	foreach (array(
		__DIR__ . '/pin-src/syslog.inc.excerpt.php',
		__DIR__ . '/pin-src/system_advanced_admin.inc.excerpt.php',
		__DIR__ . '/pin-src/util.inc.excerpt.php',
		__FILE__,
	) as $path) {
		$read = file_get_contents($path);
		$parts[] = ($read === false) ? '' : $read;
	}
	return implode("\n", $parts);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping' || $path === '/health.php') {
	$which = trim((string) shell_exec('command -v w'));
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => PRIVILEGE,
		'warn_root' => false,
		'exec' => function_exists('exec'),
		'which_w' => $which,
		'witness_path' => WITNESS_PATH,
		'conf_path' => CONF_PATH,
		'default_backend' => DEFAULT_BACKEND,
		'writer' => '/oracle/write-witness.sh',
	));
}

if ($path === '/source') {
	$src = pin_source();
	if ($src === '') {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/control') {
	$threshold = request_field('threshold', '30');
	send_json(200, run_save($threshold));
}

if ($path === '/trigger') {
	$threshold = request_field('threshold', '');
	if ($threshold === '') {
		send_json(400, array('error' => 'missing-threshold'));
	}
	send_json(200, run_save($threshold));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
