<?php
/* Lab stubs for pin excerpts. Cache write uses pin file_put_contents. */

$g = array(
	'debug' => false,
	'booting' => false,
	'conf_path' => '/conf',
	'varetc_path' => '/lab/var/etc',
	'product_label' => 'pfSense',
	'product_version_string' => '2.9.0-DEVELOPMENT',
);

$dyndns_split_domain_types = array();
$ddns_attr = array();
$config = array();

$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_notify'] = array();

if (!defined('LOG_INFO')) {
	define('LOG_INFO', 6);
}
if (!defined('LOG_ERR')) {
	define('LOG_ERR', 3);
}
if (!defined('LOG_PREFIX_DDNS')) {
	define('LOG_PREFIX_DDNS', 'ddns');
}
if (!defined('AF_INET')) {
	define('AF_INET', 2);
}
if (!defined('AF_INET6')) {
	define('AF_INET6', 10);
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
		'prefix' => $prefix,
		'message' => $message,
	);
}

function g_get(string $key, mixed $default = null): mixed {
	global $g;
	return array_key_exists($key, $g) ? $g[$key] : $default;
}

function notify_all_remote($message) {
	$GLOBALS['lab_notify'][] = $message;
}

function convert_real_interface_to_friendly_descr($if) {
	return $if;
}

function array_get_path($arr, $path, $default = null) {
	return $default;
}

function do_input_validation($postdata, $reqdfields, $reqdfieldsn, &$input_errors) {
	foreach ($reqdfields as $idx => $field) {
		if (!isset($postdata[$field]) || $postdata[$field] === '') {
			$label = $reqdfieldsn[$idx] ?? $field;
			$input_errors[] = "{$label} is required.";
		}
	}
}

function build_check_ip_mode_list() {
	return array('default' => 'Default');
}
