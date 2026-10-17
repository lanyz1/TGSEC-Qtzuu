<?php
/* pfSense CE 2.9.0-DEVELOPMENT bsnmpd conf writer gadget. Pin 9363ac5. */

const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const WITNESS = 'PFSENSE-BSNMPD-CONF-WITNESS';
const CONF_PATH = '/lab/var/etc/snmpd.conf';
const PRIVILEGE = 'page-services-snmp';

ini_set('display_errors', '0');
error_reporting(E_ALL);

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/services.inc.excerpt.php';
require __DIR__ . '/pin-src/services_snmp.php.excerpt.php';

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

function reset_lab() {
	global $config;
	$GLOBALS['lab_mwexec'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_killed'] = array();
	$config['snmpd']['syslocation'] = '';
	$config['snmpd']['syscontact'] = 'lab';
	$config['snmpd']['rocommunity'] = 'public';
	$config['snmpd']['enable'] = true;
	$config['snmpd']['trapenable'] = false;
	$config['snmpd']['modules'] = array();
	if (is_file(CONF_PATH)) {
		unlink(CONF_PATH);
	}
}

function conf_lines($body) {
	if ($body === '') {
		return array();
	}
	return preg_split("/\r\n|\n|\r/", $body);
}

function location_lines(array $lines) {
	$out = array();
	foreach ($lines as $line) {
		if (str_starts_with($line, 'location :=')) {
			$out[] = $line;
		}
	}
	return $out;
}

function community_lines(array $lines) {
	$out = array();
	foreach ($lines as $line) {
		if (str_starts_with($line, 'read :=')) {
			$out[] = $line;
		}
	}
	return $out;
}

function extra_witness_community(array $lines) {
	$hit = array();
	foreach ($lines as $line) {
		if (str_contains($line, WITNESS) && str_contains($line, 'read :=')) {
			$hit[] = $line;
		}
	}
	return $hit;
}

function run_location($location) {
	global $input_errors, $pconfig, $changes_applied, $retval;
	reset_lab();
	$input_errors = array();
	$pconfig = array();
	$changes_applied = false;
	$retval = null;

	$_POST = array(
		'enable' => 'yes',
		'syslocation' => $location,
		'syscontact' => 'lab',
		'rocommunity' => 'public',
		'pollport' => '161',
		'trapenable' => '',
		'trapserver' => '',
		'trapserverport' => '162',
		'trapstring' => '',
		'mibii' => '',
		'netgraph' => '',
		'pf' => '',
		'hostres' => '',
		'bridge' => '',
		'ucd' => '',
		'regex' => '',
		'ipprotocol' => '4',
	);

	$errors = services_snmp_save_from_post();
	if (!is_array($errors)) {
		$errors = array();
	}

	$body = '';
	if (is_file(CONF_PATH)) {
		$read = file_get_contents(CONF_PATH);
		$body = ($read === false) ? '' : $read;
	}
	$lines = conf_lines($body);
	$locs = location_lines($lines);
	$comms = community_lines($lines);
	$extra = extra_witness_community($lines);

	return array(
		'ok' => true,
		'location_posted' => $location,
		'errors' => array_values($errors),
		'write_config' => (bool) $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'retval' => $retval,
		'conf_path' => CONF_PATH,
		'conf' => $body,
		'lines' => $lines,
		'location_lines' => $locs,
		'location_line_count' => count($locs),
		'community_lines' => $comms,
		'community_line_count' => count($comms),
		'extra_witness_community' => $extra,
		'extra_witness_count' => count($extra),
		'witness_in_conf' => str_contains($body, WITNESS),
		'mwexec' => $GLOBALS['lab_mwexec'],
		'hash_rejected' => (bool) array_filter(
			$errors,
			static function ($err) {
				return is_string($err) && str_contains($err, "Invalid character '#' in system location");
			}
		),
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
		'witness' => WITNESS,
		'exec' => function_exists('exec'),
	));
}

if ($path === '/source') {
	$src = file_get_contents(__FILE__);
	if ($src === false) {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/pin/writer') {
	$src = file_get_contents(__DIR__ . '/pin-src/services.inc.excerpt.php');
	if ($src === false) {
		send_text(500, 'pin-writer-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/pin/gui') {
	$src = file_get_contents(__DIR__ . '/pin-src/services_snmp.php.excerpt.php');
	if ($src === false) {
		send_text(500, 'pin-gui-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	$body = '';
	if (is_file(CONF_PATH)) {
		$read = file_get_contents(CONF_PATH);
		$body = ($read === false) ? '' : $read;
	}
	$lines = conf_lines($body);
	send_json(200, array(
		'conf_path' => CONF_PATH,
		'conf' => $body,
		'location_lines' => location_lines($lines),
		'community_lines' => community_lines($lines),
		'extra_witness_community' => extra_witness_community($lines),
		'witness_in_conf' => str_contains($body, WITNESS),
	));
}

if ($path === '/run') {
	$case = request_field('case');
	$location = request_field('location');
	if ($case === 'control' && $location === '') {
		$location = 'office';
	}
	if ($location === '') {
		send_json(400, array('error' => 'missing-location', 'case' => $case));
	}
	$result = run_location($location);
	$result['case'] = $case;
	send_json(200, $result);
}

send_json(404, array('error' => 'not-found', 'path' => $path));
