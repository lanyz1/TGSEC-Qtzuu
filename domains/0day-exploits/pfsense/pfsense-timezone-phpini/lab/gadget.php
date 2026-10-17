<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT timezone -> php.ini gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Priv page-system-generalsetup (IDENT, no warn-root).
 */

ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-TIMEZONE-PHPINI-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-TIMEZONE-PHPINI-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const CONTROL_TZ = 'UTC';
const TRIGGER_TZ = "UTC\"\nauto_prepend_file=/oracle/prepend.php\n;";
const PHP_INI = '/usr/local/etc/php.ini';
const ZONEINFO = '/var/db/zoneinfo';
const PREPEND = '/oracle/prepend.php';
const ECHO_PHP = '/lab/echo.php';
const INI_SETUP = '/lab/pin-src/rc.php_ini_setup.excerpt.sh';

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/guiconfig.inc.excerpt.php';
require __DIR__ . '/pin-src/system.inc.excerpt.php';
require __DIR__ . '/pin-src/system.php.excerpt.php';

function reset_state() {
	global $changedesc, $changecount;
	$changedesc = '';
	$changecount = 0;
	$GLOBALS['lab_mwexec'] = array();
	$GLOBALS['lab_config'] = array(
		'system' => array(
			'hostname' => 'lab',
			'domain' => 'example.com',
			'timezone' => 'Etc/UTC',
			'timeservers' => 'pool.ntp.org',
		),
	);
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
	if (is_file(PHP_INI)) {
		unlink(PHP_INI);
	}
	if (is_file(ZONEINFO)) {
		unlink(ZONEINFO);
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

function request_timezone($default) {
	if (isset($_POST['timezone']) && is_string($_POST['timezone'])) {
		return $_POST['timezone'];
	}
	if (isset($_GET['timezone']) && is_string($_GET['timezone'])) {
		return $_GET['timezone'];
	}
	$body = request_json();
	if (isset($body['timezone']) && is_string($body['timezone'])) {
		return $body['timezone'];
	}
	return $default;
}

function run_capture(array $argv) {
	$spec = array(
		0 => array('pipe', 'r'),
		1 => array('pipe', 'w'),
		2 => array('pipe', 'w'),
	);
	$proc = proc_open($argv, $spec, $pipes, '/lab', null);
	if (!is_resource($proc)) {
		return array(
			'argv' => $argv,
			'rc' => -1,
			'stdout' => '',
			'stderr' => 'proc_open-failed',
		);
	}
	fclose($pipes[0]);
	$stdout = stream_get_contents($pipes[1]);
	$stderr = stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	$rc = proc_close($proc);
	return array(
		'argv' => $argv,
		'rc' => $rc,
		'stdout' => ($stdout === false) ? '' : $stdout,
		'stderr' => ($stderr === false) ? '' : $stderr,
	);
}

function parser_reason($stderr) {
	if (!is_string($stderr) || $stderr === '') {
		return '';
	}
	if (preg_match('/PHP:\s+syntax error[^\n]*/', $stderr, $match)) {
		return $match[0];
	}
	if (preg_match('/Unable to parse[^\n]*/', $stderr, $match)) {
		return $match[0];
	}
	return '';
}

function pin_source() {
	$files = array(
		'/lab/pin-src/system.php.excerpt.php',
		'/lab/pin-src/system.inc.excerpt.php',
		'/lab/pin-src/guiconfig.inc.excerpt.php',
		'/lab/pin-src/rc.php_ini_setup.excerpt.sh',
	);
	$parts = array();
	foreach ($files as $path) {
		$parts[] = "----- {$path} -----\n";
		$read = file_get_contents($path);
		$parts[] = ($read === false) ? '' : $read;
		if (substr(end($parts), -1) !== "\n") {
			$parts[] = "\n";
		}
	}
	return implode('', $parts);
}

function run_case($name, $timezone) {
	global $changedesc, $changecount;
	reset_state();

	$accepted = is_timezone($timezone);
	$list = system_get_timezone_list();
	if (!is_array($list)) {
		$list = array();
	}
	$in_list = in_array($timezone, $list, true);

	$_POST = array(
		'hostname' => 'lab',
		'domain' => 'example.com',
		'timezone' => $timezone,
		'timeservers' => 'pool.ntp.org',
	);

	$saved = false;
	if ($accepted) {
		system_general_save();
		system_timezone_configure();
		$saved = true;
		$sh = run_capture(array('/bin/sh', INI_SETUP));
	} else {
		$sh = array(
			'argv' => array('/bin/sh', INI_SETUP),
			'rc' => null,
			'stdout' => '',
			'stderr' => 'skipped-is-timezone',
		);
	}

	$zoneinfo = is_file(ZONEINFO) ? (string) file_get_contents(ZONEINFO) : '';
	$ini = is_file(PHP_INI) ? (string) file_get_contents(PHP_INI) : '';
	$sys = config_get_path('system', array());
	$stored = is_array($sys) && array_key_exists('timezone', $sys) ? $sys['timezone'] : null;

	$php_r = array(
		'argv' => array('php', '-c', PHP_INI, '-r', 'echo 1;'),
		'rc' => null,
		'stdout' => '',
		'stderr' => '',
	);
	$php_file = array(
		'argv' => array('php', '-c', PHP_INI, ECHO_PHP),
		'rc' => null,
		'stdout' => '',
		'stderr' => '',
	);
	if ($saved && is_file(PHP_INI)) {
		$php_r = run_capture($php_r['argv']);
		$php_file = run_capture($php_file['argv']);
	}

	$reason = parser_reason($php_r['stderr'] . "\n" . $php_file['stderr']);
	$has_prepend = (bool) preg_match('/^\s*auto_prepend_file\s*=/m', $ini);
	$tz_line = '';
	foreach (preg_split("/\r\n|\n|\r/", $ini) as $line) {
		if (str_starts_with(ltrim($line), 'date.timezone')) {
			$tz_line = $line;
			break;
		}
	}

	return array(
		'ok' => true,
		'case' => $name,
		'timezone' => $timezone,
		'is_timezone' => $accepted,
		'in_timezone_list' => $in_list,
		'saved' => $saved,
		'stored' => $stored,
		'zoneinfo' => $zoneinfo,
		'ini' => $ini,
		'date_timezone_line' => $tz_line,
		'has_auto_prepend_file' => $has_prepend,
		'php_ini_path' => PHP_INI,
		'sh' => $sh,
		'php_r' => $php_r,
		'php_file' => $php_file,
		'parser_ok' => ($reason === ''),
		'parser_reason' => $reason,
		'mwexec' => $GLOBALS['lab_mwexec'],
		'changecount' => $changecount,
		'changedesc' => $changedesc,
		'privilege' => 'page-system-generalsetup',
		'warn_root' => false,
		'witness' => witness_state(),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/health' || $path === '/health.php') {
	header('Content-Type: text/plain; charset=utf-8');
	echo "ok\n";
	exit(0);
}

if ($path === '/ping') {
	$utc_in_list = in_array('UTC', system_get_timezone_list(), true);
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'page-system-generalsetup',
		'ident' => 'page-system-generalsetup',
		'warn_root' => false,
		'exec' => function_exists('exec'),
		'utc_in_list' => $utc_in_list,
		'witness_path' => WITNESS_PATH,
		'php_ini' => PHP_INI,
	));
}

if ($path === '/source') {
	send_text(200, pin_source());
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/control') {
	send_json(200, run_case('control', request_timezone(CONTROL_TZ)));
}

if ($path === '/trigger') {
	send_json(200, run_case('trigger', request_timezone(TRIGGER_TZ)));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
