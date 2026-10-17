<?php
/* pfSense CE 2.9.0-DEVELOPMENT IGMP Proxy type gadget. Pin 9363ac5. */

const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const WITNESS = 'PFSENSE-IGMP-TYPE-WITNESS';
const CONF_PATH = '/lab/var/etc/igmpproxy.conf';
const PRIVILEGE = 'page-services-igmpproxy-edit';

ini_set('display_errors', '0');
error_reporting(E_ALL);

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/services.inc.excerpt.php';
require __DIR__ . '/pin-src/services_igmpproxy_edit.php.excerpt.php';

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
	$GLOBALS['lab_mwexec_bg'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_killed'] = array();
	$GLOBALS['lab_logs'] = array();
	$GLOBALS['lab_dirty'] = array();
	$config['igmpproxy'] = array(
		'enable' => true,
		'igmpentry' => array(),
	);
	$config['syslog'] = array();
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

function phyint_em0_lines(array $lines) {
	$out = array();
	foreach ($lines as $line) {
		if (str_starts_with($line, 'phyint em0 ')) {
			$out[] = $line;
		}
	}
	return $out;
}

function extra_witness_lines(array $lines) {
	$hit = array();
	foreach ($lines as $line) {
		if ($line !== '' && str_contains($line, WITNESS)) {
			$hit[] = $line;
		}
	}
	return $hit;
}

function seed_companion($type) {
	config_set_path('igmpproxy/igmpentry/', array(
		'ifname' => 'lan',
		'threshold' => '',
		'type' => $type,
		'address' => '192.168.1.0/24',
		'descr' => 'lab-companion',
	));
}

function run_type($type) {
	global $input_errors, $pconfig, $id, $this_igmpproxy_config;
	reset_lab();
	$input_errors = array();
	$pconfig = array();
	$id = null;
	$this_igmpproxy_config = null;

	/* Newline type is not == 'upstream', so seed a real upstream companion. */
	$companion_type = ($type === 'upstream') ? 'downstream' : 'upstream';
	seed_companion($companion_type);

	$_POST = array(
		'save' => 'yes',
		'ifname' => 'wan',
		'type' => $type,
		'threshold' => '',
		'descr' => 'lab-wan',
		'address0' => '0.0.0.0',
		'address_subnet0' => '0',
	);

	$errors = services_igmpproxy_edit_save_from_post();
	if (!is_array($errors)) {
		$errors = array();
	}

	$configured = null;
	if (!$errors) {
		$configured = services_igmpproxy_configure();
	}

	$body = '';
	if (is_file(CONF_PATH)) {
		$read = file_get_contents(CONF_PATH);
		$body = ($read === false) ? '' : $read;
	}
	$lines = conf_lines($body);
	$phyint = phyint_em0_lines($lines);
	$extra = extra_witness_lines($lines);
	$stored = config_get_path('igmpproxy/igmpentry', array());
	$stored_types = array();
	if (is_array($stored)) {
		foreach ($stored as $entry) {
			if (is_array($entry) && isset($entry['type'])) {
				$stored_types[] = strval($entry['type']);
			}
		}
	}

	return array(
		'ok' => true,
		'type_posted' => $type,
		'companion_type' => $companion_type,
		'errors' => array_values($errors),
		'write_config' => (bool) $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'configured' => $configured,
		'conf_path' => CONF_PATH,
		'conf' => $body,
		'lines' => $lines,
		'phyint_em0_lines' => $phyint,
		'phyint_em0_count' => count($phyint),
		'control_phyint' => in_array('phyint em0 upstream ratelimit 0 threshold 1', $phyint, true),
		'extra_witness_lines' => $extra,
		'extra_witness_count' => count($extra),
		'witness_in_conf' => str_contains($body, WITNESS),
		'stored_types' => $stored_types,
		'mwexec' => $GLOBALS['lab_mwexec'],
		'mwexec_bg' => $GLOBALS['lab_mwexec_bg'],
		'dirty' => $GLOBALS['lab_dirty'],
		'logs' => array_map(
			static function ($row) {
				return $row['message'];
			},
			$GLOBALS['lab_logs']
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
	$src = file_get_contents(__DIR__ . '/pin-src/services_igmpproxy_edit.php.excerpt.php');
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
		'phyint_em0_lines' => phyint_em0_lines($lines),
		'extra_witness_lines' => extra_witness_lines($lines),
		'witness_in_conf' => str_contains($body, WITNESS),
	));
}

if ($path === '/run') {
	$case = request_field('case');
	$type = request_field('type');
	if ($case === 'control' && $type === '') {
		$type = 'upstream';
	}
	if ($type === '') {
		send_json(400, array('error' => 'missing-type', 'case' => $case));
	}
	$result = run_type($type);
	$result['case'] = $case;
	send_json(200, $result);
}

send_json(404, array('error' => 'not-found', 'path' => $path));
