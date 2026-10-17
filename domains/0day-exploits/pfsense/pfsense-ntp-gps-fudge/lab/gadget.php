<?php
/* pfSense CE 2.9.0-DEVELOPMENT NTP GPS/PPS fudge gadget. Pin 9363ac5. */

const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const WITNESS = 'PFSENSE-NTP-GPS-FUDGE-WITNESS';
const CONF_PATH = '/lab/var/etc/ntpd.conf';
const PRIVILEGE = 'page-services-ntpd-gps';
const GPS_PORT = 'cua0';
const PPS_PORT = 'cua1';

ini_set('display_errors', '0');
error_reporting(E_ALL);

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/system.inc.excerpt.php';
require __DIR__ . '/pin-src/services_ntpd_gps.php.excerpt.php';
require __DIR__ . '/pin-src/services_ntpd_pps.php.excerpt.php';

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

function ensure_pps_dev($port) {
	$path = '/dev/' . $port;
	if (file_exists($path)) {
		return $path;
	}
	@file_put_contents($path, '');
	return $path;
}

function reset_lab() {
	global $config;
	$GLOBALS['lab_mwexec'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_logs'] = array();
	$config['ntpd'] = array();
	$config['system']['timeservers'] = '';
	@mkdir('/lab/var/etc', 0755, true);
	@mkdir('/lab/var/run', 0755, true);
	ensure_pps_dev(GPS_PORT);
	ensure_pps_dev(PPS_PORT);
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

function nonempty_lines(array $lines) {
	$out = array();
	foreach ($lines as $line) {
		if ($line !== '') {
			$out[] = $line;
		}
	}
	return $out;
}

function fudge_lines(array $lines) {
	$out = array();
	foreach ($lines as $line) {
		if (str_starts_with(ltrim($line), 'fudge ')) {
			$out[] = $line;
		}
	}
	return $out;
}

function extra_ntpd_lines(array $lines) {
	$out = array();
	foreach ($lines as $line) {
		$trim = ltrim($line);
		if ($trim === '' || !str_contains($trim, WITNESS)) {
			continue;
		}
		if (str_starts_with($trim, 'fudge ')) {
			continue;
		}
		$out[] = $line;
	}
	return $out;
}

function logfile_witness_lines(array $lines) {
	$out = array();
	$want = 'logfile ' . WITNESS;
	foreach ($lines as $line) {
		$trim = trim($line);
		if ($trim === $want || str_starts_with($trim, $want . ' ')) {
			$out[] = $line;
		}
	}
	return $out;
}

function mwexec_is_shell(array $cmds) {
	foreach ($cmds as $cmd) {
		if (!is_string($cmd)) {
			return true;
		}
		if (str_contains($cmd, WITNESS) || str_contains($cmd, '; w') || str_contains($cmd, '/bin/w')) {
			return true;
		}
		if (!str_contains($cmd, '/usr/local/sbin/ntpd -g -c ')) {
			return true;
		}
	}
	return false;
}

function read_conf() {
	if (!is_file(CONF_PATH)) {
		return '';
	}
	$read = file_get_contents(CONF_PATH);
	return ($read === false) ? '' : $read;
}

function run_gps($field, $value) {
	global $input_errors, $changes_applied, $retval, $config;
	reset_lab();
	$input_errors = array();
	$changes_applied = false;
	$retval = null;

	$_POST = array(
		'gpsport' => GPS_PORT,
		'gpsfudge1' => '',
		'gpsfudge2' => '',
		'gpsstratum' => '',
		'gpsrefid' => '',
	);
	if ($field === 'fudge') {
		$_POST['gpsfudge1'] = $value;
	} elseif ($field === 'fudge2') {
		$_POST['gpsfudge2'] = $value;
	} elseif ($field === 'refid') {
		$_POST['gpsrefid'] = $value;
	} elseif ($field === 'stratum') {
		$_POST['gpsstratum'] = $value;
	} else {
		return array('ok' => false, 'error' => 'bad-gps-field', 'field' => $field);
	}

	$errors = services_ntpd_gps_save_from_post();
	if (!is_array($errors)) {
		$errors = array();
	}

	$body = read_conf();
	$lines = conf_lines($body);
	$nonempty = nonempty_lines($lines);
	$fudges = fudge_lines($nonempty);
	$extra = extra_ntpd_lines($nonempty);
	$logfile = logfile_witness_lines($nonempty);
	$mwexec = $GLOBALS['lab_mwexec'];

	return array(
		'ok' => true,
		'source' => 'gps',
		'field' => $field,
		'value' => $value,
		'errors' => array_values($errors),
		'write_config' => (bool) $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'stored_fudge1' => config_get_path('ntpd/gps/fudge1'),
		'stored_fudge2' => config_get_path('ntpd/gps/fudge2'),
		'stored_refid' => config_get_path('ntpd/gps/refid'),
		'stored_stratum' => config_get_path('ntpd/gps/stratum'),
		'stored_port' => config_get_path('ntpd/gps/port'),
		'conf_path' => CONF_PATH,
		'conf' => $body,
		'lines' => $nonempty,
		'fudge_lines' => $fudges,
		'fudge_line_count' => count($fudges),
		'extra_ntpd_lines' => $extra,
		'extra_ntpd_count' => count($extra),
		'logfile_witness_lines' => $logfile,
		'logfile_witness_count' => count($logfile),
		'witness_in_conf' => str_contains($body, WITNESS),
		'mwexec' => $mwexec,
		'mwexec_shell' => mwexec_is_shell($mwexec),
		'gps_setup' => in_array('# GPS Setup', $nonempty, true),
		'pps_setup' => in_array('# PPS Setup', $nonempty, true),
	);
}

function run_pps($field, $value) {
	global $input_errors, $changes_applied, $retval;
	reset_lab();
	$input_errors = array();
	$changes_applied = false;
	$retval = null;

	$_POST = array(
		'ppsport' => PPS_PORT,
		'ppsfudge1' => '',
		'ppsstratum' => '',
		'ppsrefid' => '',
	);
	if ($field === 'fudge') {
		$_POST['ppsfudge1'] = $value;
	} elseif ($field === 'refid') {
		$_POST['ppsrefid'] = $value;
	} elseif ($field === 'stratum') {
		$_POST['ppsstratum'] = $value;
	} else {
		return array('ok' => false, 'error' => 'bad-pps-field', 'field' => $field);
	}

	$errors = services_ntpd_pps_save_from_post();
	if (!is_array($errors)) {
		$errors = array();
	}

	$body = read_conf();
	$lines = conf_lines($body);
	$nonempty = nonempty_lines($lines);
	$fudges = fudge_lines($nonempty);
	$extra = extra_ntpd_lines($nonempty);
	$logfile = logfile_witness_lines($nonempty);
	$mwexec = $GLOBALS['lab_mwexec'];

	return array(
		'ok' => true,
		'source' => 'pps',
		'field' => $field,
		'value' => $value,
		'errors' => array_values($errors),
		'write_config' => (bool) $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'stored_fudge1' => config_get_path('ntpd/pps/fudge1'),
		'stored_refid' => config_get_path('ntpd/pps/refid'),
		'stored_stratum' => config_get_path('ntpd/pps/stratum'),
		'stored_port' => config_get_path('ntpd/pps/port'),
		'conf_path' => CONF_PATH,
		'conf' => $body,
		'lines' => $nonempty,
		'fudge_lines' => $fudges,
		'fudge_line_count' => count($fudges),
		'extra_ntpd_lines' => $extra,
		'extra_ntpd_count' => count($extra),
		'logfile_witness_lines' => $logfile,
		'logfile_witness_count' => count($logfile),
		'witness_in_conf' => str_contains($body, WITNESS),
		'mwexec' => $mwexec,
		'mwexec_shell' => mwexec_is_shell($mwexec),
		'gps_setup' => in_array('# GPS Setup', $nonempty, true),
		'pps_setup' => in_array('# PPS Setup', $nonempty, true),
		'pps_dev_exists' => file_exists('/dev/' . PPS_PORT),
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
	$src = file_get_contents(__DIR__ . '/pin-src/system.inc.excerpt.php');
	if ($src === false) {
		send_text(500, 'pin-writer-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/pin/gps') {
	$src = file_get_contents(__DIR__ . '/pin-src/services_ntpd_gps.php.excerpt.php');
	if ($src === false) {
		send_text(500, 'pin-gps-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/pin/pps') {
	$src = file_get_contents(__DIR__ . '/pin-src/services_ntpd_pps.php.excerpt.php');
	if ($src === false) {
		send_text(500, 'pin-pps-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	$body = read_conf();
	$lines = nonempty_lines(conf_lines($body));
	send_json(200, array(
		'conf_path' => CONF_PATH,
		'conf' => $body,
		'lines' => $lines,
		'fudge_lines' => fudge_lines($lines),
		'extra_ntpd_lines' => extra_ntpd_lines($lines),
		'logfile_witness_lines' => logfile_witness_lines($lines),
		'witness_in_conf' => str_contains($body, WITNESS),
	));
}

if ($path === '/run') {
	$case = request_field('case');
	$source = request_field('source');
	$field = request_field('field');
	$value = request_field('value');
	if ($source === '') {
		$source = 'gps';
	}
	if ($field === '') {
		$field = 'fudge';
	}
	if ($case === 'control' && $value === '') {
		$value = '0';
	}
	if ($value === '' && $case !== 'control') {
		send_json(400, array('error' => 'missing-value', 'case' => $case, 'source' => $source, 'field' => $field));
	}
	if ($source === 'gps') {
		$result = run_gps($field, $value);
	} elseif ($source === 'pps') {
		$result = run_pps($field, $value);
	} else {
		send_json(400, array('error' => 'bad-source', 'source' => $source));
	}
	$result['case'] = $case;
	if (isset($result['ok']) && $result['ok'] === false) {
		send_json(400, $result);
	}
	send_json(200, $result);
}

send_json(404, array('error' => 'not-found', 'path' => $path));
