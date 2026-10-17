<?php
/* Lab stubs for pin excerpts. No pf, no XMLRPC, no home paths. */

$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_disconnect'] = array();
$GLOBALS['lab_logportalauth'] = array();
$GLOBALS['lab_locks'] = array();
$GLOBALS['lab_exec'] = array();
$GLOBALS['lab_config'] = array(
	'captiveportal/labzone' => array('zoneid' => 1, 'enable' => true),
);

function gettext($text) {
	return $text;
}

function captiveportal_syslog($message) {
	$GLOBALS['lab_logs'][] = $message;
}

function lock($name, $flags = 0) {
	$GLOBALS['lab_locks'][] = array('lock' => $name, 'flags' => $flags);
	return $name;
}

function unlock($lock) {
	$GLOBALS['lab_locks'][] = array('unlock' => $lock);
}

function config_get_path($path, $default = null) {
	if (array_key_exists($path, $GLOBALS['lab_config'])) {
		return $GLOBALS['lab_config'][$path];
	}
	return $default;
}

function captiveportal_disconnect($dbent, $term_cause = 1, $stop_time = null, $carp_loop = false) {
	$GLOBALS['lab_disconnect'][] = array(
		'username' => isset($dbent[4]) ? $dbent[4] : null,
		'sessionid' => isset($dbent[5]) ? $dbent[5] : null,
		'ip' => isset($dbent[2]) ? $dbent[2] : null,
		'mac' => isset($dbent[3]) ? $dbent[3] : null,
		'term_cause' => $term_cause,
	);
	return true;
}

function captiveportal_logportalauth($user, $mac, $ip, $reason) {
	$GLOBALS['lab_logportalauth'][] = array(
		'user' => $user,
		'mac' => $mac,
		'ip' => $ip,
		'reason' => $reason,
	);
}

function captiveportal_xmlrpc_sync_get_details(&$syncip, &$port, &$username, &$password, $carp_loop = false) {
	return false;
}

class pfsense_xmlrpc_client {
	function setConnectionData($syncip, $syncport, $syncuser, $syncpass) {
	}
	function set_noticefile($name) {
	}
	function xmlrpc_method($method, $args) {
		return false;
	}
}
