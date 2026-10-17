<?php
/* Lab stubs for pin excerpts. Color is stored raw; display interpolates into class=. */

if (!function_exists('mb_strlen')) {
	function mb_strlen($string, $encoding = null) {
		return strlen((string) $string);
	}
}

$GLOBALS['lab_config'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_headers'] = array();
$GLOBALS['lab_dirty'] = array();
$GLOBALS['lab_html'] = '';
$GLOBALS['lab_filter_configure'] = 0;

function gettext($text) {
	return $text;
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
	return true;
}

function set_filter_rules_order($rule) {
	return false;
}

function set_anynat_rules_order($kind, $rule) {
	return false;
}

function mark_subsystem_dirty($subsystem) {
	$GLOBALS['lab_dirty'][] = $subsystem;
}

function filter_configure() {
	$GLOBALS['lab_filter_configure']++;
	return 0;
}
