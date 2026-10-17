<?php
/* Lab stubs for pin excerpts. tzsetup is recorded, not executed. */

$changedesc = '';
$changecount = 0;
$g = array(
	'debug' => false,
	'default_timezone' => 'Etc/UTC',
);

$GLOBALS['lab_config'] = array(
	'system' => array(
		'hostname' => 'lab',
		'domain' => 'example.com',
		'timezone' => 'Etc/UTC',
		'timeservers' => 'pool.ntp.org',
	),
);
$GLOBALS['lab_mwexec'] = array();

function gettext($text) {
	return $text;
}

function g_get($key, $default = null) {
	global $g;
	if (is_array($g) && array_key_exists($key, $g)) {
		return $g[$key];
	}
	return $default;
}

function is_platform_booting() {
	return false;
}

function config_get_path(string $path, $default = null) {
	$cur = $GLOBALS['lab_config'];
	foreach (explode('/', $path) as $part) {
		if (!is_array($cur) || !array_key_exists($part, $cur)) {
			return $default;
		}
		$cur = $cur[$part];
	}
	return $cur;
}

function config_set_path(string $path, $value, $default = null) {
	$parts = explode('/', $path);
	$ref = &$GLOBALS['lab_config'];
	$last = array_pop($parts);
	foreach ($parts as $part) {
		if (!isset($ref[$part]) || !is_array($ref[$part])) {
			$ref[$part] = array();
		}
		$ref = &$ref[$part];
	}
	$ref[$last] = $value;
	return $value;
}

function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	$GLOBALS['lab_mwexec'][] = $command;
	return 0;
}
