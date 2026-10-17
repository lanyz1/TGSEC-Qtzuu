<?php
/* Lab stubs so pin interface_wireless_clone interpolates {$baseif}. */

$g = array('tmp_path' => '/lab/tmp');
$GLOBALS['lab_live_ifs'] = array();
$GLOBALS['lab_config'] = array();
$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_rename'] = array();
$GLOBALS['lab_destroy'] = array();

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

function get_interface_arr($flush = false) {
	return $GLOBALS['lab_live_ifs'];
}

function get_interface_mac($interface) {
	return '00:00:00:00:00:01';
}

function pfSense_interface_destroy($interface) {
	$GLOBALS['lab_destroy'][] = $interface;
	return true;
}

function pfSense_interface_rename($old, $new) {
	$GLOBALS['lab_rename'][] = array('old' => $old, 'new' => $new);
	return true;
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
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

function get_configured_interface_list($with_disabled = false) {
	return array();
}
