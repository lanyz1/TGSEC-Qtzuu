<?php
/* Lab stubs for pin excerpts. mwexec records argv and does not exec. */

if (!defined('LOG_PREFIX_NTP')) {
	define('LOG_PREFIX_NTP', 'NTP');
}

$g = array(
	'debug' => false,
	'booting' => false,
	'varetc_path' => '/lab/var/etc',
	'varrun_path' => '/lab/var/run',
	'product_label' => 'pfSense',
	'product_version_string' => '2.9.0-DEVELOPMENT',
);

$config = array(
	'ntpd' => array(),
	'system' => array(
		'hostname' => 'lab',
		'domain' => 'example.test',
		'timeservers' => '',
	),
);

$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_serial_ports'] = array(
	'cua0' => '/dev/cua0',
	'cua1' => '/dev/cua1',
);

function gettext($text) {
	return $text;
}

function localize_text($text, ...$args) {
	if (count($args) === 0) {
		return $text;
	}
	return vsprintf($text, $args);
}

function logger($priority, $message, $prefix = null, $facilities = null) {
	$GLOBALS['lab_logs'][] = array(
		'priority' => $priority,
		'message' => $message,
		'prefix' => $prefix,
	);
}

function g_get(string $key, mixed $default = null): mixed {
	global $g;
	return array_key_exists($key, $g) ? $g[$key] : $default;
}

function is_platform_booting(): bool {
	return false;
}

function get_serial_ports($short = false) {
	return $GLOBALS['lab_serial_ports'];
}

function system_ntp_setup_gps($serialport) {
	$serialports = get_serial_ports(true);
	if (!array_key_exists($serialport, $serialports)) {
		return false;
	}
	return true;
}

function system_ntp_setup_pps($serialport) {
	$serialports = get_serial_ports(true);
	if (!array_key_exists($serialport, $serialports)) {
		return false;
	}
	return true;
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

function array_del_path(array &$arr, string $path, $default = null) {
	$vpath = explode('/', $path);
	$vkey = array_pop($vpath);
	$el =& $arr;
	foreach ($vpath as $key) {
		if (mb_strlen($key) == 0) {
			continue;
		}
		if (is_array($el) && array_key_exists($key, $el)) {
			$el =& $el[$key];
		} else {
			return $default;
		}
	}

	if (!(is_array($el) && array_key_exists($vkey, $el))) {
		return $default;
	}

	$ret = $el[$vkey];
	unset($el[$vkey]);
	return ($ret);
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

function config_del_path(string $path, $default = null) {
	global $config;
	return is_array($config) ? array_del_path($config, $path, $default) : $default;
}

function config_path_enabled(string $path, $enable_key = "enable", $default = false) {
	global $config;
	return is_array($config) ? array_path_enabled($config, $path, $enable_key, $default) : $default;
}
