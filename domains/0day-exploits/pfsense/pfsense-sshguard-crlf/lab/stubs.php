<?php
/* Lab stubs for pin excerpts. mwexec_bg records pin argv and runs the sshguard reader. */

$g = array('varlog_path' => '/var/log');
$GLOBALS['lab_config'] = array();
$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_backend'] = array(
	'output' => '',
	'exit' => null,
	'path' => null,
);
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_numericint_calls'] = array();

function gettext($text) {
	return $text;
}

function g_get(string $key, mixed $default = null): mixed {
	global $g;
	return array_key_exists($key, $g) ? $g[$key] : $default;
}

function config_get_path(string $path, $default = null) {
	if (array_key_exists($path, $GLOBALS['lab_config'])) {
		return $GLOBALS['lab_config'][$path];
	}
	return $default;
}

function config_set_path(string $path, $value, $default = null) {
	$GLOBALS['lab_config'][$path] = $value;
	return $value;
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function is_subnet($subnet) {
	if (!is_string($subnet) || $subnet === '') {
		return false;
	}
	$parts = explode('/', $subnet, 2);
	if (count($parts) !== 2) {
		return false;
	}
	if (filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
		return false;
	}
	if (!ctype_digit($parts[1])) {
		return false;
	}
	$bits = intval($parts[1], 10);
	$max = str_contains($parts[0], ':') ? 128 : 32;
	return ($bits >= 0 && $bits <= $max);
}

function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	$GLOBALS['lab_mwexec'][] = $command;
	if (str_contains($command, '/usr/local/sbin/sshguard')) {
		$output = array();
		$retval = 0;
		exec('/lab/bin/sshguard-backend-exec /usr/local/etc/sshguard.conf 2>&1', $output, $retval);
		$text = implode("\n", $output);
		$backend = null;
		foreach ($output as $line) {
			if (str_starts_with($line, 'BACKEND=')) {
				$backend = substr($line, strlen('BACKEND='));
			}
		}
		$GLOBALS['lab_backend'] = array(
			'output' => $text,
			'exit' => $retval,
			'path' => $backend,
		);
		return $retval;
	}
	return 0;
}

function mwexec_bg($command, $clearsigmask = false) {
	return mwexec($command, false, $clearsigmask, true);
}
