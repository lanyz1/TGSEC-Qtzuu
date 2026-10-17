<?php
/* Lab stubs. mwexec is /bin/sh -c of the pin command string. */

$g = array(
	'varrun_path' => '/lab/run',
	'etc_path' => '/lab/etc',
	'debug' => false,
);

$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_mwexec_out'] = array();
$GLOBALS['lab_logs'] = array();

if (!defined('LOG_ERR')) {
	define('LOG_ERR', 3);
}
if (!defined('LOG_NOTICE')) {
	define('LOG_NOTICE', 5);
}
if (!defined('LOG_PREFIX_GWMON')) {
	define('LOG_PREFIX_GWMON', 'dpinger');
}

function gettext($text) {
	return $text;
}

function localize_text($text, ...$args) {
	if (count($args) === 0) {
		return $text;
	}
	return vsprintf($text, $args);
}

function logger($priority, $message, $prefix = '') {
	$GLOBALS['lab_logs'][] = array(
		'priority' => $priority,
		'message' => $message,
		'prefix' => $prefix,
	);
}

function g_get(string $key, mixed $default = null) : mixed {
	global $g;
	return array_key_exists($key, $g) ? $g[$key] : $default;
}

function stop_dpinger($gwname = '') {
	return;
}

function interface_wait_tentative($if) {
	return true;
}

function get_real_interface($interface, $family = 'all') {
	return $interface;
}

function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	$retval = 0;
	$GLOBALS['lab_mwexec'][] = $command;
	$descriptors = array(
		0 => array('pipe', 'r'),
		1 => array('pipe', 'w'),
		2 => array('pipe', 'w'),
	);
	$proc = proc_open(array('/bin/sh', '-c', $command), $descriptors, $pipes);
	if (!is_resource($proc)) {
		return 1;
	}
	fclose($pipes[0]);
	$stdout = stream_get_contents($pipes[1]);
	$stderr = stream_get_contents($pipes[2]);
	fclose($pipes[1]);
	fclose($pipes[2]);
	$retval = proc_close($proc);
	$GLOBALS['lab_mwexec_out'][] = array(
		'stdout' => is_string($stdout) ? $stdout : '',
		'stderr' => is_string($stderr) ? $stderr : '',
		'retval' => $retval,
	);
	return $retval;
}
