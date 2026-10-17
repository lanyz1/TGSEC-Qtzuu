<?php
/* Lab stubs for pin excerpts. mwexec_bg records argv and does not exec. */

define('LOG_PREFIX_IGMPPROXY', 'IGMP Proxy');

$g = array(
	'debug' => false,
	'booting' => false,
	'varetc_path' => '/lab/var/etc',
	'varrun_path' => '/lab/var/run',
	'product_label' => 'pfSense',
	'product_version_string' => '2.9.0-DEVELOPMENT',
);

$config = array(
	'interfaces' => array(
		'wan' => array(
			'enable' => true,
			'if' => 'em0',
			'ipaddr' => '203.0.113.1',
		),
		'lan' => array(
			'enable' => true,
			'if' => 'em1',
			'ipaddr' => '192.168.1.1',
		),
	),
	'igmpproxy' => array(
		'enable' => true,
		'igmpentry' => array(),
	),
	'syslog' => array(),
);

$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_mwexec_bg'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_killed'] = array();
$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_dirty'] = array();
$GLOBALS['lab_realif'] = array(
	'wan' => 'em0',
	'lan' => 'em1',
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

function logger($priority, $message, $prefix = '') {
	$GLOBALS['lab_logs'][] = array(
		'priority' => $priority,
		'prefix' => $prefix,
		'message' => $message,
	);
}

function g_get(string $key, mixed $default = null): mixed {
	global $g;
	return array_key_exists($key, $g) ? $g[$key] : $default;
}

function is_platform_booting(): bool {
	return false;
}

function isvalidproc($proc) {
	return false;
}

function killbyname($procname) {
	$GLOBALS['lab_killed'][] = $procname;
}

function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	$GLOBALS['lab_mwexec'][] = $command;
	return 0;
}

function mwexec_bg($command, $clearsigmask = false) {
	$GLOBALS['lab_mwexec_bg'][] = $command;
	return mwexec($command, false, $clearsigmask, true);
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function mark_subsystem_dirty($subsystem = "") {
	$GLOBALS['lab_dirty'][] = $subsystem;
}

function get_configured_interface_list(bool $with_disabled = false): array {
	$iflist = [];
	foreach (config_get_path('interfaces', []) as $if => $if_detail) {
		if ($with_disabled || isset($if_detail['enable'])) {
			$iflist[$if] = $if;
		}
	}

	return ($iflist);
}

function get_real_interface($interface = "wan", $family = "all", $realv6iface = false, $flush = false) {
	$map = $GLOBALS['lab_realif'];
	if (is_string($interface) && array_key_exists($interface, $map)) {
		return $map[$interface];
	}
	return $interface;
}

function is_subnetv4($subnet) {
	if (!is_string($subnet) || $subnet === '') {
		return false;
	}
	$parts = explode('/', $subnet, 2);
	if (count($parts) !== 2) {
		return false;
	}
	if (filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
		return false;
	}
	if (!ctype_digit($parts[1])) {
		return false;
	}
	$mask = intval($parts[1]);
	return ($mask >= 0 && $mask <= 32);
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
		if (isset($el[$vkey]) && is_array($el[$vkey])) {
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
