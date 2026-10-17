<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT OpenVPN learn-address CN gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Priv: OpenVPN cert client CN, gated on Unbound Register OpenVPN clients.
 */

putenv('PATH=/lab/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin');
ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-OVPN-LEARN-CN-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-OVPN-LEARN-CN-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const PIN_SCRIPT = '/usr/local/sbin/openvpn.learn-address.sh';
const PIN_SOURCE = '/lab/pin-src/openvpn.learn-address.sh';
const CONTROL_CN = 'client1';
const TRIGGER_CN = '$(w)';
const DOMAIN = 'example.com';
const OP = 'add';
const IP = '10.8.0.2';
const GATE_UNBOUND = '/lab/gate/unbound';
const GATE_REGOVPNC = '/lab/gate/regovpnclients';
const SU_LOG = '/oracle/su.log';
const CONTROL_LOG = '/oracle/unbound-control.log';
const CHECKCONF_LOG = '/oracle/unbound-checkconf.log';

function reset_oracle() {
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
	foreach (array(SU_LOG, CONTROL_LOG, CHECKCONF_LOG) as $path) {
		if (is_file($path)) {
			unlink($path);
		}
	}
	foreach (glob('/var/unbound/openvpn.client.*') ?: array() as $path) {
		if (is_file($path)) {
			unlink($path);
		}
	}
}

function read_file($path) {
	if (!is_file($path)) {
		return '';
	}
	$read = file_get_contents($path);
	return ($read === false) ? '' : $read;
}

function witness_state() {
	$exists = is_file(WITNESS_PATH);
	$body = $exists ? read_file(WITNESS_PATH) : '';
	return array(
		'exists' => $exists,
		'body' => $body,
		'path' => WITNESS_PATH,
	);
}

function gates_ok() {
	return is_file(GATE_UNBOUND) && is_file(GATE_REGOVPNC);
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

function run_learn($case, $cn) {
	reset_oracle();
	if (!gates_ok()) {
		return array(
			'ok' => false,
			'error' => 'gate-missing',
			'case' => $case,
			'gates' => array(
				'unbound' => is_file(GATE_UNBOUND),
				'regovpnclients' => is_file(GATE_REGOVPNC),
			),
			'witness' => witness_state(),
		);
	}
	if (!is_dir('/var/unbound')) {
		mkdir('/var/unbound', 0777, true);
	}
	$cmd = implode(' ', array(
		escapeshellarg(PIN_SCRIPT),
		escapeshellarg(DOMAIN),
		escapeshellarg(OP),
		escapeshellarg(IP),
		escapeshellarg($cn),
	));
	$output = array();
	$rc = 0;
	exec($cmd . ' 2>&1', $output, $rc);
	$conf = '/var/unbound/openvpn.client.' . IP . '.conf';
	$conf_body = read_file($conf);
	$su_log = read_file(SU_LOG);
	$control_log = read_file(CONTROL_LOG);
	$local_data_name = $cn . '.' . DOMAIN;
	$local_data_line = 'local-data: "' . $cn . '.' . DOMAIN . ' A ' . IP . '"';
	return array(
		'ok' => true,
		'case' => $case,
		'domain' => DOMAIN,
		'op' => OP,
		'ip' => IP,
		'cn' => $cn,
		'script' => PIN_SCRIPT,
		'script_rc' => $rc,
		'script_output' => implode("\n", $output),
		'conf_path' => $conf,
		'conf_body' => $conf_body,
		'conf_exists' => is_file($conf),
		'su_log' => $su_log,
		'unbound_control_log' => $control_log,
		'checkconf_log' => read_file(CHECKCONF_LOG),
		'local_data_name' => $local_data_name,
		'local_data_line' => $local_data_line,
		'local_data_plant' => (strpos($conf_body, $local_data_line) !== false),
		'local_data_control' => (strpos($su_log, 'local_data ' . $local_data_name) !== false)
			|| (strpos($control_log, 'local_data ' . $local_data_name) !== false),
		'gates' => array(
			'unbound' => true,
			'regovpnclients' => true,
		),
		'witness' => witness_state(),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/health') {
	send_text(200, "ok\n");
}

if ($path === '/ping') {
	$which = trim((string) shell_exec('command -v w'));
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'openvpn-cert-client-cn',
		'gate' => 'unbound/regovpnclients',
		'exec' => function_exists('exec'),
		'which_w' => $which,
		'witness_path' => WITNESS_PATH,
		'gates' => array(
			'unbound' => is_file(GATE_UNBOUND),
			'regovpnclients' => is_file(GATE_REGOVPNC),
		),
	));
}

if ($path === '/source') {
	$src = file_get_contents(PIN_SOURCE);
	if ($src === false) {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/control') {
	send_json(200, run_learn('control', CONTROL_CN));
}

if ($path === '/trigger') {
	send_json(200, run_learn('trigger', TRIGGER_CN));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
