<?php
/* Lab stubs for pin excerpts. $portlist is em0/em1 only. */

if (!defined('LOG_INFO')) {
	define('LOG_INFO', 6);
}
if (!defined('LOG_ERR')) {
	define('LOG_ERR', 3);
}
if (!defined('LOG_DEBUG')) {
	define('LOG_DEBUG', 7);
}

$GLOBALS['lab_live_ifs'] = array('em0', 'em1');
$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_filter_configure'] = 0;
$GLOBALS['lab_bring_down'] = array();
$GLOBALS['lab_configure'] = array();

$config = array();
$portlist = array();
$input_errors = array();
$action_msg = '';
$class = '';

function lab_reset_state() {
	global $config, $portlist, $input_errors, $action_msg, $class, $g;

	$config = array(
		'interfaces' => array(
			'wan' => array(
				'descr' => 'WAN',
				'if' => 'em0',
				'enable' => true,
			),
			'lan' => array(
				'descr' => 'LAN',
				'if' => 'em1',
				'enable' => true,
			),
		),
	);
	$portlist = array(
		'em0' => array('descr' => 'em0'),
		'em1' => array('descr' => 'em1'),
	);
	$input_errors = array();
	$action_msg = '';
	$class = '';
	$GLOBALS['lab_logs'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_filter_configure'] = 0;
	$GLOBALS['lab_bring_down'] = array();
	$GLOBALS['lab_configure'] = array();
	if (is_array($g) && !empty($g['tmp_path']) && is_dir($g['tmp_path'])) {
		foreach (glob($g['tmp_path'] . '/*') as $tmpf) {
			if (is_file($tmpf)) {
				unlink($tmpf);
			}
		}
	}
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

function logger($priority, $message) {
	$GLOBALS['lab_logs'][] = array(
		'priority' => $priority,
		'message' => $message,
	);
}

function does_interface_exist($interface, $flush = false) {
	if (!$interface) {
		return false;
	}
	return in_array($interface, $GLOBALS['lab_live_ifs'], true);
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function filter_configure() {
	$GLOBALS['lab_filter_configure']++;
	return 0;
}

function interface_bring_down($interface) {
	$GLOBALS['lab_bring_down'][] = $interface;
}

function interface_configure($interface, $reload = false) {
	$GLOBALS['lab_configure'][] = $interface;
}

function interface_is_vlan($if = NULL) {
	return NULL;
}

function pfSense_interface_destroy($realif) {
	return true;
}

function pfSense_interface_rename($old, $new) {
	return true;
}

function get_interface_mac($realif) {
	return '00:00:00:00:00:00';
}

function get_interface_arr($flush = false) {
	return $GLOBALS['lab_live_ifs'];
}

function convert_friendly_interface_to_friendly_descr($interface) {
	return strtoupper($interface);
}

function config_get_path(string $path, $default = null) {
	global $config;
	if (!is_array($config)) {
		return $default;
	}
	if ($path === '' || $path === '/') {
		return $config;
	}
	$parts = explode('/', $path);
	$el = $config;
	foreach ($parts as $key) {
		if ($key === '') {
			continue;
		}
		if (!is_array($el) || !array_key_exists($key, $el)) {
			return $default;
		}
		$el = $el[$key];
	}
	if (($default !== null) && ($el === '')) {
		return $default;
	}
	return $el;
}

function config_set_path(string $path, $value, $default = null) {
	global $config;
	if (!is_array($config)) {
		$config = array();
	}
	if ($path === '') {
		if (!is_array($value)) {
			return $default;
		}
		$config = $value;
		return $value;
	}
	$parts = explode('/', $path);
	$el = &$config;
	$last = array_pop($parts);
	foreach ($parts as $key) {
		if ($key === '') {
			continue;
		}
		if (!isset($el[$key]) || !is_array($el[$key])) {
			$el[$key] = array();
		}
		$el = &$el[$key];
	}
	$el[$last] = $value;
	return $value;
}

function config_del_path(string $path, $default = null) {
	global $config;
	$parts = explode('/', $path);
	$last = array_pop($parts);
	$el = &$config;
	foreach ($parts as $key) {
		if ($key === '' ) {
			continue;
		}
		if (!is_array($el) || !array_key_exists($key, $el)) {
			return $default;
		}
		$el = &$el[$key];
	}
	if (is_array($el) && array_key_exists($last, $el)) {
		$val = $el[$last];
		unset($el[$last]);
		return $val;
	}
	return $default;
}

function config_init_path(string $path) {
	global $config;
	if (!is_array($config)) {
		$config = array();
	}
	$parts = explode('/', $path);
	$el = &$config;
	foreach ($parts as $key) {
		if ($key === '') {
			continue;
		}
		if (!isset($el[$key]) || !is_array($el[$key])) {
			$el[$key] = array();
		}
		$el = &$el[$key];
	}
	return true;
}

function config_path_enabled(string $path, $enable_key = "enable", $default = false) {
	$arr = config_get_path($path, null);
	if (!is_array($arr)) {
		return $default;
	}
	return array_key_exists($enable_key, $arr) && $arr[$enable_key] !== null;
}
