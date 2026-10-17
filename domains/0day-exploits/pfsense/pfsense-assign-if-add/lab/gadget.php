<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT assign add if_add gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Priv page-interfaces-assignnetworkports then GET interfaces.php?if=optN.
 */

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));
ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-ASSIGN-IF-ADD-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-ASSIGN-IF-ADD-WITNESS';
const IFCONFIG_LOG = '/oracle/ifconfig-calls';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const PRIVILEGE = 'page-interfaces-assignnetworkports';

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/globals.inc.excerpt.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces_assign.php.excerpt.php';
require __DIR__ . '/pin-src/interfaces.php.excerpt.php';

function reset_oracle() {
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
	if (is_file(IFCONFIG_LOG)) {
		unlink(IFCONFIG_LOG);
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

function ifconfig_log_text() {
	if (!is_file(IFCONFIG_LOG)) {
		return '';
	}
	$read = file_get_contents(IFCONFIG_LOG);
	return ($read === false) ? '' : $read;
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

function request_if_add() {
	if (isset($_POST['if_add']) && is_string($_POST['if_add'])) {
		return $_POST['if_add'];
	}
	if (isset($_GET['if_add']) && is_string($_GET['if_add'])) {
		return $_GET['if_add'];
	}
	$raw = file_get_contents('php://input');
	if (is_string($raw) && $raw !== '') {
		$parsed = json_decode($raw, true);
		if (is_array($parsed) && isset($parsed['if_add']) && is_string($parsed['if_add'])) {
			return $parsed['if_add'];
		}
	}
	return '';
}

function pin_source() {
	$files = array(
		__DIR__ . '/pin-src/globals.inc.excerpt.php',
		__DIR__ . '/pin-src/util.inc.excerpt.php',
		__DIR__ . '/pin-src/interfaces.inc.excerpt.php',
		__DIR__ . '/pin-src/interfaces_assign.php.excerpt.php',
		__DIR__ . '/pin-src/interfaces.php.excerpt.php',
	);
	$parts = array();
	foreach ($files as $path) {
		$src = file_get_contents($path);
		if ($src === false) {
			return false;
		}
		$parts[] = $src;
	}
	return implode("\n", $parts);
}

function lab_common($if_add) {
	global $config, $portlist, $input_errors, $g;

	$regex = g_get('wireless_regex');
	return array(
		'if_add' => $if_add,
		'regex' => $regex,
		'regex_match' => (is_string($regex) && preg_match($regex, $if_add) === 1),
		'regex_ath0_id' => (is_string($regex) && preg_match($regex, 'ath0;id') === 1),
		'portlist_member' => array_key_exists($if_add, $portlist),
		'portlist' => array_keys($portlist),
		'stored' => $config['interfaces'] ?? array(),
		'wan_if' => config_get_path('interfaces/wan/if'),
		'lan_if' => config_get_path('interfaces/lan/if'),
		'opt1_if' => config_get_path('interfaces/opt1/if'),
		'opt1_wireless' => config_get_path('interfaces/opt1/wireless'),
		'errors' => $input_errors,
		'write_config' => $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'filter_configure' => $GLOBALS['lab_filter_configure'],
		'baseif' => interface_get_wireless_base($if_add),
		'cloneif' => interface_get_wireless_clone($if_add),
		'tmp_path' => $g['tmp_path'] ?? '',
		'ifconfig_log' => ifconfig_log_text(),
		'witness' => witness_state(),
		'logs' => array_map(
			static function ($row) {
				return $row['message'];
			},
			$GLOBALS['lab_logs']
		),
	);
}

function run_control($if_add) {
	global $input_errors;

	reset_oracle();
	lab_reset_state();
	$_POST = array(
		'Submit' => 'Save',
		'wan' => $if_add,
		'lan' => 'em1',
	);
	$_REQUEST = $_POST;
	assign_submit_remap();
	$out = lab_common($if_add);
	$out['case'] = 'control';
	$out['ok'] = true;
	$out['submit_exec'] = ifconfig_log_text() !== '' || witness_state()['exists'];
	$out['input_error_count'] = is_array($input_errors) ? count($input_errors) : 0;
	return $out;
}

function run_trigger($if_add) {
	reset_oracle();
	lab_reset_state();
	$_POST = array(
		'add' => '1',
		'if_add' => $if_add,
	);
	$_REQUEST = $_POST;
	$newif = assign_add_if_add();
	$page = array();
	if (is_string($newif) && $newif !== '') {
		$_REQUEST = array('if' => $newif);
		$page = interfaces_page_get($newif);
	}
	$out = lab_common($if_add);
	$out['case'] = 'trigger';
	$out['ok'] = true;
	$out['newif'] = $newif;
	$out['page'] = $page;
	return $out;
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	$which = trim((string) shell_exec('command -v w'));
	$regex = g_get('wireless_regex');
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => PRIVILEGE,
		'exec' => function_exists('exec'),
		'which_w' => $which,
		'witness_path' => WITNESS_PATH,
		'regex' => $regex,
		'regex_ath0_id' => (is_string($regex) && preg_match($regex, 'ath0;id') === 1),
		'regex_ath0_w' => (is_string($regex) && preg_match($regex, 'ath0;w') === 1),
		'regex_anchored' => (is_string($regex) && str_ends_with($regex, '$/')),
	));
}

if ($path === '/source') {
	$src = pin_source();
	if ($src === false) {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/control') {
	$if_add = request_if_add();
	if ($if_add === '') {
		send_json(400, array('error' => 'missing-if_add'));
	}
	send_json(200, run_control($if_add));
}

if ($path === '/trigger') {
	$if_add = request_if_add();
	if ($if_add === '') {
		send_json(400, array('error' => 'missing-if_add'));
	}
	send_json(200, run_trigger($if_add));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
