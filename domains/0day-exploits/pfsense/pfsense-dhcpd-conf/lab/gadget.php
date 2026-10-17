<?php
/* pfSense CE 2.9.0-DEVELOPMENT ISC dhcpd.conf filename gadget. Pin 9363ac5. */

const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const WITNESS = 'PFSENSE-DHCPD-CONF-WITNESS';
const CONF_PATH = '/lab/var/dhcpd/etc/dhcpd.conf';
const PRIVILEGE = 'page-services-dhcpserver-editstaticmapping';
const IFACE = 'lan';
const MAP_MAC = '00:00:00:00:00:01';
const MAP_IP = '192.0.2.10';

ini_set('display_errors', '0');
error_reporting(E_ALL);

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/services.inc.excerpt.php';
require __DIR__ . '/pin-src/services_dhcp_edit.php.excerpt.php';

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
	$GLOBALS['lab_dirty'] = array();
	$config['dhcpbackend'] = 'isc';
	$config['dhcpd']['lan']['enable'] = true;
	$config['dhcpd']['lan']['staticmap'] = array();
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

function filename_lines(array $lines) {
	$out = array();
	foreach ($lines as $line) {
		if (str_starts_with(ltrim($line), 'filename ')) {
			$out[] = $line;
		}
	}
	return $out;
}

function extra_witness_statements(array $lines) {
	$hit = array();
	foreach ($lines as $line) {
		$trim = trim($line);
		if ($trim === '' || str_starts_with($trim, 'filename ')) {
			continue;
		}
		if (str_contains($line, WITNESS)) {
			$hit[] = $line;
		}
	}
	return $hit;
}

function run_filename($filename) {
	global $input_errors, $pconfig, $if, $id, $this_map_config, $config;
	reset_lab();
	$input_errors = array();
	$pconfig = array();
	$if = IFACE;
	$id = null;
	$this_map_config = null;

	$_POST = array(
		'mac' => MAP_MAC,
		'cid' => '',
		'ipaddr' => MAP_IP,
		'hostname' => '',
		'descr' => '',
		'filename' => $filename,
		'rootpath' => '',
		'filename32' => '',
		'filename64' => '',
		'filename32arm' => '',
		'filename64arm' => '',
		'uefihttpboot' => '',
		'ldap' => '',
	);

	$errors = services_dhcp_edit_save_from_post();
	if (!is_array($errors)) {
		$errors = array();
	}

	$retval = null;
	if (!$errors) {
		$retval = services_dhcpdv4_configure();
	}

	$body = '';
	if (is_file(CONF_PATH)) {
		$read = file_get_contents(CONF_PATH);
		$body = ($read === false) ? '' : $read;
	}
	$lines = conf_lines($body);
	$fnames = filename_lines($lines);
	$extra = extra_witness_statements($lines);
	$stored = config_get_path('dhcpd/lan/staticmap/0/filename', '');

	return array(
		'ok' => true,
		'filename_posted' => $filename,
		'filename_stored' => $stored,
		'errors' => array_values($errors),
		'write_config' => (bool) $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'dirty' => $GLOBALS['lab_dirty'],
		'retval' => $retval,
		'backend' => dhcp_get_backend(),
		'conf_path' => CONF_PATH,
		'conf' => $body,
		'lines' => $lines,
		'filename_lines' => $fnames,
		'filename_line_count' => count($fnames),
		'extra_witness_statements' => $extra,
		'extra_witness_count' => count($extra),
		'witness_in_conf' => str_contains($body, WITNESS),
		'mwexec' => $GLOBALS['lab_mwexec'],
		'staticmap' => config_get_path('dhcpd/lan/staticmap', array()),
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
		'backend' => dhcp_get_backend(),
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
	$src = file_get_contents(__DIR__ . '/pin-src/services_dhcp_edit.php.excerpt.php');
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
		'filename_lines' => filename_lines($lines),
		'extra_witness_statements' => extra_witness_statements($lines),
		'witness_in_conf' => str_contains($body, WITNESS),
	));
}

if ($path === '/run') {
	$case = request_field('case');
	$filename = request_field('filename');
	if ($case === 'control' && $filename === '') {
		$filename = 'pxelinux.0';
	}
	if ($filename === '') {
		send_json(400, array('error' => 'missing-filename', 'case' => $case));
	}
	$result = run_filename($filename);
	$result['case'] = $case;
	send_json(200, $result);
}

send_json(404, array('error' => 'not-found', 'path' => $path));
