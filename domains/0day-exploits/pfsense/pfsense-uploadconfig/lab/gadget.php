<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT hidden uploadconfig leftover gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9. Priv page-hidden-uploadconfiguration.
 */

ini_set('display_errors', '0');
error_reporting(E_ALL);

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/uploadconfig.php.excerpt.php';
require __DIR__ . '/pin-src/priv.defs.inc.excerpt.php';

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

function pin_file($name) {
	$path = __DIR__ . '/pin-src/' . $name;
	$src = file_get_contents($path);
	return ($src === false) ? '' : $src;
}

function ident_block($src, $ident) {
	$marker = '##|*IDENT=' . $ident;
	$idx = strpos($src, $marker);
	if ($idx === false) {
		return '';
	}
	$prefix = substr($src, 0, $idx);
	$start = strrpos($prefix, '##|+PRIV');
	$end = strpos($src, '##|-PRIV', $idx);
	if ($start === false || $end === false) {
		return '';
	}
	return substr($src, $start, ($end + strlen('##|-PRIV')) - $start);
}

function ident_has_warn($block) {
	return str_contains($block, '##|*WARN=') || str_contains($block, 'standard-warning-root');
}

function source_text() {
	$parts = array(
		pin_file('uploadconfig.php.excerpt.php'),
		pin_file('priv.defs.inc.excerpt.php'),
		pin_file('diag_backup.php.excerpt.php'),
	);
	return implode("\n", $parts);
}

function run_pin($mode) {
	lab_reset();
	ob_start();
	uploadconfig_handle();
	$out = ob_get_clean();
	$conf = lab_conf_path();
	$blob = is_file($conf) ? (string) file_get_contents($conf) : '';
	lab_maybe_witness();
	lab_write_state();
	$ident = ident_block(pin_file('uploadconfig.php.excerpt.php'), PRIVILEGE);
	$backup_ident = ident_block(pin_file('diag_backup.php.excerpt.php'), 'page-diagnostics-backup-restore');
	$priv = isset($GLOBALS['priv_list'][PRIVILEGE]) ? $GLOBALS['priv_list'][PRIVILEGE] : array();
	return array(
		'ok' => true,
		'mode' => $mode,
		'pin_output' => $out,
		'install_called' => (bool) $GLOBALS['lab_install_called'],
		'reboot_requested' => (bool) $GLOBALS['lab_reboot_requested'],
		'blob_on_disk' => ($blob !== ''),
		'blob' => $blob,
		'conf_path' => $conf,
		'tmp_path' => lab_tmp_config_path(),
		'privilege' => PRIVILEGE,
		'warn_root' => ident_has_warn($ident),
		'backup_warn_root' => ident_has_warn($backup_ident),
		'priv_has_warn' => isset($priv['warn']),
		'witness' => witness_state(),
	);
}

function oracle_payload() {
	$state = lab_read_state();
	$conf = lab_conf_path();
	$blob = is_file($conf) ? (string) file_get_contents($conf) : '';
	$w = witness_state();
	$install = !empty($state['install_called']);
	$reboot = !empty($state['reboot_requested']);
	return array(
		'ok' => true,
		'exists' => $w['exists'],
		'present' => $w['exists'],
		'body' => $w['body'],
		'path' => $w['path'],
		'install_called' => $install,
		'reboot_requested' => $reboot,
		'blob_on_disk' => ($blob !== ''),
		'blob' => $blob,
		'conf_path' => $conf,
		'witness' => $w,
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	$ident = ident_block(pin_file('uploadconfig.php.excerpt.php'), PRIVILEGE);
	$priv = isset($GLOBALS['priv_list'][PRIVILEGE]) ? $GLOBALS['priv_list'][PRIVILEGE] : array();
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => PRIVILEGE,
		'warn_root' => ident_has_warn($ident),
		'priv_has_warn' => isset($priv['warn']),
		'witness_path' => WITNESS_PATH,
		'conf_path' => lab_conf_path(),
	));
}

if ($path === '/source') {
	$src = source_text();
	if ($src === '') {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/control') {
	send_json(200, run_pin('control'));
}

if ($path === '/trigger') {
	send_json(200, run_pin('trigger'));
}

if ($path === '/oracle') {
	send_json(200, oracle_payload());
}

send_json(404, array('error' => 'not-found', 'path' => $path));
