<?php
/* Lab stubs for pin excerpts. */

$GLOBALS['lab_config'] = array(
	'system/webgui/protocol' => 'https',
	'system/hostname' => 'pfsense',
	'system/domain' => 'home.arpa',
	'system/webgui/althostnames' => '',
	'dyndnses/dyndns' => array(),
	'dnsupdates/dnsupdate' => array(),
);
$GLOBALS['lab_error_form'] = array();
$GLOBALS['lab_security_checks_disabled'] = false;

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

function config_del_path(string $path, $default = null) {
	if (array_key_exists($path, $GLOBALS['lab_config'])) {
		$ret = $GLOBALS['lab_config'][$path];
		unset($GLOBALS['lab_config'][$path]);
		return $ret;
	}
	return $default;
}

function config_path_enabled(string $path, $enable_key = "enable", $default = false) {
	$full = $path . '/' . $enable_key;
	if (array_key_exists($full, $GLOBALS['lab_config'])) {
		return true;
	}
	return $default;
}

function is_ipaddr($ip) {
	if (!is_string($ip) || $ip === '') {
		return false;
	}
	return filter_var($ip, FILTER_VALIDATE_IP) !== false;
}

function security_checks_disabled() {
	return (bool) $GLOBALS['lab_security_checks_disabled'];
}

function display_error_form($http_code, $message) {
	$GLOBALS['lab_error_form'] = array(
		'status' => (string) $http_code,
		'message' => (string) $message,
	);
}
