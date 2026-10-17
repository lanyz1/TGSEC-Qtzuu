<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT VLAN parent membership gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Priv page-interfaces-vlan-edit. Ioctl leftover, not shell.
 */

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));
ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-VLAN-PARENT-IOCTL-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-VLAN-PARENT-IOCTL-WITNESS';
const IFCONFIG_LOG = '/oracle/ifconfig-calls';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const PRIVILEGE = 'page-interfaces-vlan-edit';
const PORTLIST_IF = 'em0';
const HIDDEN_IF = 'em1';
const TAG = '10';

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/globals.inc.excerpt.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces_vlan_edit.php.excerpt.php';

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

function pin_source() {
	$files = array(
		__DIR__ . '/pin-src/globals.inc.excerpt.php',
		__DIR__ . '/pin-src/util.inc.excerpt.php',
		__DIR__ . '/pin-src/interfaces.inc.excerpt.php',
		__DIR__ . '/pin-src/interfaces_vlan_edit.php.excerpt.php',
		__DIR__ . '/stubs.php',
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

function request_field($name, $default = '') {
	if (isset($_POST[$name]) && is_string($_POST[$name])) {
		return $_POST[$name];
	}
	if (isset($_GET[$name]) && is_string($_GET[$name])) {
		return $_GET[$name];
	}
	$raw = file_get_contents('php://input');
	if (is_string($raw) && $raw !== '') {
		$parsed = json_decode($raw, true);
		if (is_array($parsed) && isset($parsed[$name]) && is_string($parsed[$name])) {
			return $parsed[$name];
		}
	}
	return $default;
}

function vlandev_in_log($parent, $log) {
	return (strpos($log, 'vlandev ' . $parent) !== false);
}

function run_vlan($case, $parent) {
	global $portlist, $input_errors, $id, $this_vlan_config, $confif;

	reset_oracle();
	lab_reset_state();
	$portlist = vlan_edit_build_portlist();
	$id = null;
	$this_vlan_config = null;
	$confif = '';
	$input_errors = array();

	$_POST = array(
		'if' => $parent,
		'tag' => TAG,
		'tag_type' => 'ctag',
		'pcp' => '0',
		'descr' => '',
		'save' => 'yes',
	);
	$_REQUEST = $_POST;

	vlan_edit_save();

	$log = ifconfig_log_text();
	$vlan = $GLOBALS['lab_vlan'];
	$creates = $GLOBALS['lab_vlan_create'];
	$create_if = '';
	if (isset($creates[0]) && is_array($creates[0])) {
		$create_if = strval($creates[0]['if'] ?? '');
	}
	$mwexec = $GLOBALS['lab_mwexec'];
	$escaped = escapeshellarg($parent);
	$unescaped_create = false;
	foreach ($mwexec as $cmd) {
		$cmd = strval($cmd);
		if (strpos($cmd, 'vlan create vlandev') === false) {
			continue;
		}
		if (strpos($cmd, 'vlandev ' . $escaped) === false &&
		    strpos($cmd, 'vlandev ' . $parent) !== false &&
		    strpos($parent, ';') !== false) {
			$unescaped_create = true;
		}
	}

	return array(
		'ok' => true,
		'case' => $case,
		'parent' => $parent,
		'tag' => TAG,
		'privilege' => PRIVILEGE,
		'portlist' => array_keys($portlist),
		'portlist_member' => array_key_exists($parent, $portlist),
		'does_exist' => does_interface_exist($parent),
		'hidden' => ($parent === HIDDEN_IF),
		'errors' => is_array($input_errors) ? $input_errors : array(),
		'write_config' => $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'vlanif' => is_array($vlan) ? ($vlan['vlanif'] ?? null) : null,
		'stored_if' => is_array($vlan) ? ($vlan['if'] ?? null) : null,
		'create_if' => $create_if,
		'escaped_if' => $escaped,
		'unescaped_create' => $unescaped_create,
		'mwexec' => $mwexec,
		'vlandev_logged' => vlandev_in_log($parent, $log),
		'ifconfig_log' => $log,
		'witness' => witness_state(),
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
		'portlist_if' => PORTLIST_IF,
		'hidden_if' => HIDDEN_IF,
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

if ($path === '/run') {
	$case = request_field('case');
	$parent = request_field('if');
	if ($case === 'control') {
		if ($parent === '') {
			$parent = PORTLIST_IF;
		}
		send_json(200, run_vlan($case, $parent));
	}
	if ($case === 'trigger') {
		if ($parent === '') {
			$parent = HIDDEN_IF;
		}
		send_json(200, run_vlan($case, $parent));
	}
	if ($case === 'reject') {
		if ($parent === '') {
			$parent = 'missing0';
		}
		send_json(200, run_vlan($case, $parent));
	}
	if ($case === 'shell') {
		if ($parent === '') {
			$parent = 'em1;w';
		}
		send_json(200, run_vlan($case, $parent));
	}
	send_json(400, array('error' => 'bad-case', 'case' => $case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
