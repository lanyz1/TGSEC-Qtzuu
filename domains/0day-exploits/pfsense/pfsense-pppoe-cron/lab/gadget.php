<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT PPPoE periodic-reset crontab gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9. Priv page-interfaces-ppps-edit.
 */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/globals.inc.excerpt.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces.inc.excerpt.php';
require __DIR__ . '/pin-src/services.inc.excerpt.php';
require __DIR__ . '/pin-src/interfaces_ppps_edit.php.excerpt.php';

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));
ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-PPPOE-CRON-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-PPPOE-CRON-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const CRONTAB_PATH = '/etc/crontab';
const W_CMD = '/lab/bin/w';
const CONTROL_CMD = '/var/etc/pppoe_restart_pppoe0';
const EXTRA_LINE = '* * * * * root /lab/bin/w';
const HOUR_BREAKOUT = "24\n* * * * * root /lab/bin/w\n#";

$GLOBALS['lab_logs'] = array();

function reset_oracle() {
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
}

function reset_config() {
	global $config;
	$config = array(
		'cron' => array(
			'item' => array(),
		),
	);
	$GLOBALS['lab_logs'] = array();
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

function pin_source() {
	$names = array(
		'interfaces.inc.excerpt.php',
		'services.inc.excerpt.php',
		'interfaces_ppps_edit.php.excerpt.php',
		'util.inc.excerpt.php',
	);
	$out = '';
	foreach ($names as $name) {
		$path = __DIR__ . '/pin-src/' . $name;
		$out .= "===== {$name} =====\n";
		$read = file_get_contents($path);
		$out .= ($read === false) ? '' : $read;
		$out .= "\n";
	}
	return $out;
}

function crontab_field_ok($field, $lo, $hi) {
	if (!is_string($field) || $field === '') {
		return false;
	}
	if ($field === '*') {
		return true;
	}
	if (preg_match('/^\*\/([0-9]+)$/', $field, $m)) {
		return intval($m[1]) > 0;
	}
	foreach (explode(',', $field) as $part) {
		if (preg_match('/^([0-9]+)-([0-9]+)$/', $part, $m)) {
			$a = intval($m[1]);
			$b = intval($m[2]);
			if ($a < $lo || $b > $hi || $a > $b) {
				return false;
			}
			continue;
		}
		if (preg_match('/^[0-9]+$/', $part)) {
			$n = intval($part);
			if ($n < $lo || $n > $hi) {
				return false;
			}
			continue;
		}
		return false;
	}
	return true;
}

function parse_system_crontab($text) {
	$jobs = array();
	$env = array(
		'SHELL' => '/bin/sh',
		'PATH' => '/usr/bin:/bin',
	);
	foreach (explode("\n", $text) as $raw) {
		$line = rtrim($raw, "\r");
		$trim = trim($line);
		if ($trim === '' || str_starts_with($trim, '#')) {
			continue;
		}
		if (preg_match('/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/', $trim, $m)) {
			$env[$m[1]] = $m[2];
			continue;
		}
		$parts = preg_split('/\s+/', $trim, 7);
		if (!is_array($parts) || count($parts) < 7) {
			$jobs[] = array(
				'valid' => false,
				'reason' => 'too-few-fields',
				'line' => $trim,
				'user' => '',
				'command' => '',
			);
			continue;
		}
		$min = $parts[0];
		$hour = $parts[1];
		$mday = $parts[2];
		$month = $parts[3];
		$wday = $parts[4];
		$user = $parts[5];
		$command = $parts[6];
		if (
			!crontab_field_ok($min, 0, 59) ||
			!crontab_field_ok($hour, 0, 23) ||
			!crontab_field_ok($mday, 1, 31) ||
			!crontab_field_ok($month, 1, 12) ||
			!crontab_field_ok($wday, 0, 7)
		) {
			$jobs[] = array(
				'valid' => false,
				'reason' => 'bad-time',
				'line' => $trim,
				'user' => $user,
				'command' => $command,
			);
			continue;
		}
		if ($user === '' || $command === '') {
			$jobs[] = array(
				'valid' => false,
				'reason' => 'empty-user-or-command',
				'line' => $trim,
				'user' => $user,
				'command' => $command,
			);
			continue;
		}
		$jobs[] = array(
			'valid' => true,
			'reason' => '',
			'line' => $trim,
			'minute' => $min,
			'hour' => $hour,
			'mday' => $mday,
			'month' => $month,
			'wday' => $wday,
			'user' => $user,
			'command' => $command,
			'env' => $env,
		);
	}
	return $jobs;
}

function stub_cron_run_job($job) {
	$shell = '/bin/sh';
	$path = '/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin';
	if (isset($job['env']['SHELL']) && is_string($job['env']['SHELL']) && $job['env']['SHELL'] !== '') {
		$shell = $job['env']['SHELL'];
	}
	if (isset($job['env']['PATH']) && is_string($job['env']['PATH']) && $job['env']['PATH'] !== '') {
		$path = $job['env']['PATH'];
	}
	$command = $job['command'];
	$full = 'PATH=' . escapeshellarg($path) . ' ' . $shell . ' -c ' . escapeshellarg($command);
	$output = array();
	$rc = 0;
	exec($full . ' 2>&1', $output, $rc);
	return array(
		'user' => $job['user'],
		'command' => $command,
		'rc' => $rc,
		'output' => implode("\n", $output),
	);
}

function hour_breakout_errors($hour) {
	$saved = $_POST;
	$_POST = array(
		'pppoe-reset-type' => 'custom',
		'pppoe_resethour' => $hour,
		'pppoe_resetminute' => '0',
	);
	$errors = ppps_edit_reset_validate();
	$_POST = $saved;
	return $errors;
}

function build_post($ptpid, $hour, $minute) {
	return array(
		'type' => 'pppoe',
		'ptpid' => $ptpid,
		'pppoe-reset-type' => 'custom',
		'pppoe_resethour' => $hour,
		'pppoe_resetminute' => $minute,
		'pppoe_resetdate' => '',
	);
}

function run_case($name, $ptpid, $hour, $minute) {
	global $config;
	reset_config();
	reset_oracle();
	file_put_contents(CRONTAB_PATH, '');

	$_POST = build_post($ptpid, $hour, $minute);
	$input_errors = ppps_edit_reset_validate();
	$saved = empty($input_errors);
	if ($saved) {
		handle_pppoe_reset($_POST);
		configure_cron();
	}

	$crontab = file_get_contents(CRONTAB_PATH);
	if ($crontab === false) {
		$crontab = '';
	}
	$jobs = parse_system_crontab($crontab);
	$ran = array();
	$skipped = array();
	foreach ($jobs as $job) {
		if (empty($job['valid'])) {
			$skipped[] = $job;
			continue;
		}
		$ran[] = stub_cron_run_job($job);
	}

	$cron_items = config_get_path('cron/item', array());
	$extra_in_file = str_contains($crontab, EXTRA_LINE);
	$extra_valid = false;
	$extra_ran = false;
	foreach ($jobs as $job) {
		if (!empty($job['valid']) && $job['user'] === 'root' && $job['command'] === W_CMD) {
			$extra_valid = true;
		}
	}
	foreach ($ran as $row) {
		if (($row['command'] ?? '') === W_CMD && ($row['user'] ?? '') === 'root') {
			$extra_ran = true;
		}
	}

	$valid_count = 0;
	foreach ($jobs as $job) {
		if (!empty($job['valid'])) {
			$valid_count++;
		}
	}

	return array(
		'ok' => true,
		'case' => $name,
		'privilege' => 'page-interfaces-ppps-edit',
		'ptpid' => $ptpid,
		'hour' => $hour,
		'minute' => $minute,
		'pppif' => $_POST['type'] . $_POST['ptpid'],
		'input_errors' => $input_errors,
		'saved' => $saved,
		'cron_item_count' => is_array($cron_items) ? count($cron_items) : 0,
		'cron_items' => $cron_items,
		'crontab' => $crontab,
		'jobs' => $jobs,
		'valid_job_count' => $valid_count,
		'ran' => $ran,
		'skipped' => $skipped,
		'extra_line_in_file' => $extra_in_file,
		'extra_line_valid' => $extra_valid,
		'extra_line_ran' => $extra_ran,
		'proxyuser_in_crontab' => str_contains($crontab, 'HTTP_PROXY_AUTH='),
		'witness' => witness_state(),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	$which = trim((string) shell_exec('command -v w'));
	$hour_errors = hour_breakout_errors(HOUR_BREAKOUT);
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'page-interfaces-ppps-edit',
		'exec' => function_exists('exec'),
		'which_w' => $which,
		'witness_path' => WITNESS_PATH,
		'hour_and_bug_accepts_breakout' => count($hour_errors) === 0,
		'hour_breakout_errors' => $hour_errors,
	));
}

if ($path === '/source') {
	$src = pin_source();
	send_text(200, $src);
}

if ($path === '/control') {
	send_json(200, run_case('control', '0', '1', '0'));
}

if ($path === '/trigger') {
	$ptpid = "0\n" . EXTRA_LINE;
	send_json(200, run_case('trigger', $ptpid, '1', '0'));
}

if ($path === '/oracle') {
	$crontab = file_get_contents(CRONTAB_PATH);
	if ($crontab === false) {
		$crontab = '';
	}
	$state = witness_state();
	$state['crontab'] = $crontab;
	$state['extra_line_in_file'] = str_contains($crontab, EXTRA_LINE);
	send_json(200, $state);
}

send_json(404, array('error' => 'not-found', 'path' => $path));
