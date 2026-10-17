<?php
/* Lab stubs for pin excerpts. mwexec records argv and does not exec. */

$g = array(
	'debug' => false,
	'booting' => false,
	'varetc_path' => '/lab/var/etc',
	'varrun_path' => '/lab/var/run',
	'product_label' => 'pfSense',
	'product_version_string' => '2.9.0-DEVELOPMENT',
);

$config = array(
	'snmpd' => array(
		'enable' => true,
		'pollport' => '161',
		'syslocation' => '',
		'syscontact' => 'lab',
		'rocommunity' => 'public',
		'trapenable' => false,
		'trapserver' => '',
		'trapserverport' => '162',
		'trapstring' => '',
		'ipprotocol' => '4',
		'modules' => array(),
	),
	'system' => array(
		'hostname' => 'lab',
		'domain' => 'example.test',
	),
);

$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_killed'] = array();

function gettext($text) {
	return $text;
}

function g_get(string $key, mixed $default = null): mixed {
	global $g;
	return array_key_exists($key, $g) ? $g[$key] : $default;
}

function is_platform_booting(): bool {
	return false;
}

function sigkillbypid($pidfile, $sig, int $waitfor = 0): int {
	$GLOBALS['lab_killed'][] = array('pidfile' => $pidfile, 'sig' => $sig);
	return 0;
}

function is_process_running(string $name): bool {
	return false;
}

function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	$GLOBALS['lab_mwexec'][] = $command;
	return 0;
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function array_get_path(array &$arr, string $path, $default = null) {
	$vpath = explode('/', $path);
	$el = $arr;
	foreach ($vpath as $key) {
		if (mb_strlen($key) == 0) {
			continue;
		}
		if (is_array($el) && array_key_exists($key, $el)) {
			$el = $el[$key];
		} else {
			return ($default);
		}
	}

	if (($default !== null) && ($el === '')) {
		return ($default);
	}

	return ($el);
}

function array_set_path(array &$arr, string $path, $value, $default = null) {
	$vpath = explode('/', $path);
	if (($path != '') && ($vpath[array_key_last($vpath)] === '')) {
		$append = true;
	} else {
		$append = false;
	}

	do {
		$vkey = array_pop($vpath);
	} while (isset($vkey) && (mb_strlen($vkey) == 0));

	if ($vkey == null) {
		if ($append) {
			$arr[] = (is_array($value)) ? $value : [$value];
		} else {
			$arr = (is_array($value)) ? $value : [$value];
		}
		return ($value);
	}

	$el =& $arr;
	foreach ($vpath as $key) {
		if (mb_strlen($key) == 0) {
			continue;
		}
		if (array_key_exists($key, $el) && !empty($el[$key])) {
			if (!is_array($el[$key])) {
				return ($default);
			}
		} else {
			$el[$key] = [];
		}
		$el =& $el[$key];
	}

	if ($append) {
		if (is_array($el[$vkey])) {
			$el[$vkey][] = $value;
		} else {
			$el[$vkey] = [$value];
		}
	} else {
		$el[$vkey] = $value;
	}

	return ($value);
}

function array_path_enabled(array &$arr, string $path, $enable_key = "enable", $default = false) {
	$el = array_get_path($arr, $path, $default);
	return is_array($el) ? isset($el[$enable_key]) : $default;
}

function config_get_path(string $path, $default = null) {
	global $config;
	return is_array($config) ? array_get_path($config, $path, $default) : $default;
}

function config_set_path(string $path, $value, $default = null) {
	global $config;
	return is_array($config) ? array_set_path($config, $path, $value, $default) : $default;
}

function config_path_enabled(string $path, $enable_key = "enable", $default = false) {
	global $config;
	return is_array($config) ? array_path_enabled($config, $path, $enable_key, $default) : $default;
}

function is_port($port, $validate_name = true) {
	if (ctype_digit(strval($port)) && ((intval($port) >= 1) && (intval($port) <= 65535))) {
		return true;
	}
	return false;
}

function is_ipaddr($ip) {
	if (!is_string($ip) || $ip === '') {
		return false;
	}
	return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function do_input_validation($postdata, $reqdfields, $reqdfieldsn, &$input_errors) {
	if (!is_array($input_errors)) {
		$input_errors = array();
	}
	for ($i = 0; $i < count($reqdfields); $i++) {
		$field = $reqdfields[$i];
		if (!isset($postdata[$field]) || $postdata[$field] === '') {
			$name = $reqdfieldsn[$i] ?? $field;
			$input_errors[] = sprintf("%s is required.", $name);
		}
	}
}
