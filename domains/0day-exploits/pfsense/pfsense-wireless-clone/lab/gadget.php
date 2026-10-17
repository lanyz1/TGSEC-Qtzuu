<?php
/* pfSense CE 2.9.0-DEVELOPMENT wireless clone parent-if gadget. Pin 9363ac5. */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/guiconfig.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces_wireless_edit.php.excerpt.php';

ini_set('display_errors', '0');
error_reporting(E_ERROR | E_PARSE);

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));

const WITNESS = 'PFSENSE-WIRELESS-CLONE-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-WIRELESS-CLONE-WITNESS';
const IFCONFIG_LOG = '/oracle/ifconfig-calls';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const PRIVILEGE = 'page-interfaces-wireless-edit';

function reset_lab(): void {
	global $g, $id, $this_clone_config, $input_errors, $clone, $wlan_modes;
	$GLOBALS['lab_live_ifs'] = array();
	$GLOBALS['lab_config'] = array();
	$GLOBALS['lab_logs'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_rename'] = array();
	$GLOBALS['lab_destroy'] = array();
	$id = null;
	$this_clone_config = null;
	$input_errors = array();
	$clone = array();
	$wlan_modes = array(
		'bss' => 'Infrastructure (BSS)',
		'adhoc' => 'Ad-hoc (IBSS)',
		'hostap' => 'Access Point',
	);
	if (!is_dir($g['tmp_path'])) {
		mkdir($g['tmp_path'], 0777, true);
	}
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
	if (is_file(IFCONFIG_LOG)) {
		unlink(IFCONFIG_LOG);
	}
}

function witness_state(): array {
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

function ifconfig_log_text(): string {
	if (!is_file(IFCONFIG_LOG)) {
		return '';
	}
	$read = file_get_contents(IFCONFIG_LOG);
	return ($read === false) ? '' : $read;
}

function send_json(int $status, array $payload): void {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
	exit(0);
}

function send_text(int $status, string $body): void {
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

function request_field(string $name, string $default = ''): string {
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

function pin_source(): string {
	$parts = array();
	foreach (array(
		__DIR__ . '/pin-src/guiconfig.inc.excerpt.php',
		__DIR__ . '/pin-src/interfaces.inc.excerpt.php',
		__DIR__ . '/pin-src/interfaces_wireless_edit.php.excerpt.php',
	) as $path) {
		$parts[] = (string) file_get_contents($path);
	}
	return implode("\n", $parts);
}

function run_clone(string $case): array {
	global $input_errors, $clone;

	reset_lab();

	$posted_if = request_field('if');
	$posted_mode = request_field('mode', 'bss');
	$posted_descr = request_field('descr', '');
	$posted_cloneif = request_field('cloneif', '');

	$_POST = array(
		'save' => 'yes',
		'if' => $posted_if,
		'mode' => $posted_mode,
		'descr' => $posted_descr,
		'cloneif' => $posted_cloneif,
	);

	wireless_edit_save();

	$stored_if = is_array($clone) ? strval($clone['if'] ?? '') : '';
	$stored_cloneif = is_array($clone) ? strval($clone['cloneif'] ?? '') : '';
	$baseif = ($stored_if === '') ? '' : interface_get_wireless_base($stored_if);
	$hidden_copied = ($posted_cloneif !== '' && $stored_cloneif === $posted_cloneif);

	return array(
		'ok' => true,
		'case' => $case,
		'posted_if' => $posted_if,
		'posted_mode' => $posted_mode,
		'posted_cloneif' => $posted_cloneif,
		'stored_if' => $stored_if,
		'cloneif' => $stored_cloneif,
		'baseif' => $baseif,
		'hidden_cloneif_copied' => $hidden_copied,
		'clone_ok' => (bool) $GLOBALS['lab_write_config'],
		'write_config' => $GLOBALS['lab_write_config'],
		'errors' => is_array($input_errors) ? $input_errors : array(),
		'ifconfig_log' => ifconfig_log_text(),
		'rename' => $GLOBALS['lab_rename'],
		'logs' => array_map(
			static function ($row) {
				return $row['message'];
			},
			$GLOBALS['lab_logs']
		),
		'witness' => witness_state(),
		'privilege' => PRIVILEGE,
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	$which = trim((string) shell_exec('command -v w'));
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => PRIVILEGE,
		'exec' => function_exists('exec'),
		'which_w' => $which,
		'witness_path' => WITNESS_PATH,
	));
}

if ($path === '/source') {
	$src = pin_source();
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, witness_state() + array(
		'ifconfig_log' => ifconfig_log_text(),
	));
}

if ($path === '/run') {
	$case = request_field('case');
	if ($case !== 'control' && $case !== 'trigger') {
		send_json(400, array('error' => 'bad-case', 'case' => $case));
	}
	if (request_field('if') === '') {
		send_json(400, array('error' => 'missing-if'));
	}
	send_json(200, run_clone($case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
