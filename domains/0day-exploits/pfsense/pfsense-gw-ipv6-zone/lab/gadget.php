<?php
/**
 * pfSense CE 2.9.0-DEVELOPMENT IPv6 link-local zone into dpinger.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Priv page-system-gateways-editgateway then apply.
 */

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));
ini_set('display_errors', '0');
error_reporting(0);

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/Net_IPv6.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/gwlb.inc.excerpt.php';

const WITNESS = 'PFSENSE-GW-IPV6-ZONE-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-GW-IPV6-ZONE-WITNESS';
const DPINGER_ARGV_PATH = '/oracle/dpinger-argv';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const PRIVILEGE = 'page-system-gateways-editgateway';

function reset_oracle() {
	global $lab_mwexec, $lab_mwexec_out, $lab_logs;
	$lab_mwexec = array();
	$lab_mwexec_out = array();
	$lab_logs = array();
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
	if (is_file(DPINGER_ARGV_PATH)) {
		unlink(DPINGER_ARGV_PATH);
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

function dpinger_argv_text() {
	if (!is_file(DPINGER_ARGV_PATH)) {
		return '';
	}
	$read = file_get_contents(DPINGER_ARGV_PATH);
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

function source_blob() {
	$parts = array(
		file_get_contents(__DIR__ . '/pin-src/util.inc.excerpt.php'),
		file_get_contents(__DIR__ . '/pin-src/gwlb.inc.excerpt.php'),
		file_get_contents(__DIR__ . '/stubs.php'),
		file_get_contents(__FILE__),
	);
	foreach ($parts as $idx => $part) {
		if ($part === false) {
			$parts[$idx] = '';
		}
	}
	return implode("\n", $parts);
}

function lab_gateway($monitor, $gateway_ip) {
	$gw = array(
		'name' => 'LABGW',
		'interface' => 'wan',
		'ipprotocol' => 'inet6',
		'gwifip' => '192.0.2.1',
		'monitor' => $monitor,
		'gateway' => $gateway_ip,
		'action_disable' => false,
	);
	/* setup_gateways_monitor: empty monitor copies the gateway IP. */
	if (empty($gw['monitor']) || !is_ipaddr($gw['monitor'])) {
		if (is_ipaddr($gw['gateway'])) {
			$gw['monitor'] = $gw['gateway'];
		}
	}
	return $gw;
}

function run_case($monitor, $gateway_ip) {
	global $lab_mwexec, $lab_mwexec_out;
	reset_oracle();
	$posted_monitor = $monitor;
	$valid_posted = is_ipaddrv6($posted_monitor);
	$valid_gateway = ($gateway_ip !== '') ? is_ipaddrv6($gateway_ip) : false;
	$name_ok = is_validaliasname('LABGW');
	$gw = lab_gateway($posted_monitor, $gateway_ip);
	$valid_monitor = is_ipaddrv6($gw['monitor']);
	$started = false;
	if (is_ipaddr($gw['monitor'])) {
		$started = start_dpinger($gw);
	}
	$cmds = is_array($lab_mwexec) ? $lab_mwexec : array();
	$command = isset($cmds[0]) ? strval($cmds[0]) : '';
	return array(
		'ok' => true,
		'privilege' => PRIVILEGE,
		'posted_monitor' => $posted_monitor,
		'gateway_ip' => $gateway_ip,
		'monitor_after' => $gw['monitor'],
		'name' => $gw['name'],
		'name_ok' => $name_ok,
		'is_ipaddrv6_posted' => (bool)$valid_posted,
		'is_ipaddrv6_gateway' => (bool)$valid_gateway,
		'is_ipaddrv6_monitor' => (bool)$valid_monitor,
		'is_ipaddr_monitor' => (bool)is_ipaddr($gw['monitor']),
		'started' => $started,
		'mwexec' => $cmds,
		'command' => $command,
		'dpinger_argv' => dpinger_argv_text(),
		'mwexec_out' => $lab_mwexec_out,
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
	));
}

if ($path === '/source') {
	$src = source_blob();
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/reset') {
	reset_oracle();
	send_json(200, witness_state() + array('reset' => true));
}

if ($path === '/run') {
	$case = request_field('case');
	$monitor = request_field('monitor');
	$gateway_ip = request_field('gateway');
	if ($case === 'control' || $case === 'trigger') {
		$payload = run_case($monitor, $gateway_ip);
		$payload['case'] = $case;
		send_json(200, $payload);
	}
	send_json(400, array('error' => 'bad-case', 'case' => $case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
