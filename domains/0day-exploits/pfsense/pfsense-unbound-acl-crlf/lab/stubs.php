<?php
/* Lab stubs for pin Unbound ACL writer. */

$g = array(
	'unbound_chroot_path' => '/var/unbound',
	'tmp_path' => '/lab/tmp',
	'varrun_path' => '/lab/run',
);
$config = array();
$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_dirty'] = array();
$GLOBALS['lab_checkconf_calls'] = 0;
$GLOBALS['lab_header'] = '';
$input_errors = array();
$networkacl = array();
$id = null;
$retval = 0;

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

function g_has(string $key, bool $valid = false): bool {
	global $g;
	return is_array($g) && array_key_exists($key, $g);
}

function g_get(string $key, mixed $default = null): mixed {
	global $g;
	return (g_has($key, true) ? $g[$key] : $default);
}

function lab_array_get_path($arr, string $path, $default = null) {
	if ($path === '') {
		return $arr;
	}
	$cur = $arr;
	foreach (explode('/', $path) as $key) {
		if (!is_array($cur) || !array_key_exists($key, $cur)) {
			return $default;
		}
		$cur = $cur[$key];
	}
	return $cur;
}

function lab_array_set_path(&$arr, string $path, $value) {
	$keys = explode('/', $path);
	$cur = &$arr;
	foreach ($keys as $i => $key) {
		if ($i === count($keys) - 1) {
			$cur[$key] = $value;
			return $value;
		}
		if (!isset($cur[$key]) || !is_array($cur[$key])) {
			$cur[$key] = array();
		}
		$cur = &$cur[$key];
	}
	return $value;
}

function config_get_path(string $path, $default = null) {
	global $config;
	if (str_ends_with(trim($path), '/') || str_contains($path, '//')) {
		return $default;
	}
	return is_array($config) ? lab_array_get_path($config, $path, $default) : $default;
}

function config_set_path(string $path, $value, $default = null) {
	global $config;
	if (str_contains($path, '//') || $path === '/') {
		return $default;
	}
	if (!is_array($config)) {
		$config = array();
	}
	return lab_array_set_path($config, $path, $value);
}

function config_path_enabled(string $path, $enable_key = "enable", $default = false) {
	$node = config_get_path($path, null);
	if (!is_array($node)) {
		return $default;
	}
	return array_key_exists($enable_key, $node) && $node[$enable_key] !== null;
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function mark_subsystem_dirty($subsystem) {
	$GLOBALS['lab_dirty'][$subsystem] = true;
}

function clear_subsystem_dirty($subsystem) {
	unset($GLOBALS['lab_dirty'][$subsystem]);
}

function pfSenseHeader($url) {
	$GLOBALS['lab_header'] = $url;
}

function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	global $g;
	$GLOBALS['lab_mwexec'][] = $command;
	$retval = 0;
	if ($background) {
		exec("/usr/bin/nohup $command > /dev/null 2>&1 & echo $!");
		return 0;
	}
	$outputarray = array();
	exec("$command 2>&1", $outputarray, $retval);
	return $retval;
}

function test_unbound_config($unboundcfg, &$output) {
	$GLOBALS['lab_checkconf_calls']++;
	$output[] = 'lab-checkconf-called';
	return 0;
}

function is_subnetv6($subnet) {
	return is_subnet($subnet) === 6;
}

function services_unbound_configure($restart_dhcp = true, $interface = '') {
	global $g;
	create_unbound_chroot_path();
	unbound_acls_config();
	$include = unbound_access_lists_include_line("");
	$unboundcfgtxt = "server:\n    verbosity: 0\n\n# Access lists\n{$include}\n";
	file_put_contents("{$g['unbound_chroot_path']}/unbound.conf", $unboundcfgtxt);
	do_as_unbound_user("start");
	return 0;
}
