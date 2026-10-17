<?php
/* Lab stubs for pin excerpts. Nested config_get/set_path plus no-op sort/write_config. */

$GLOBALS['config'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';

function gettext($text) {
	return $text;
}

function cpelements_sort() {
	global $cpzone;

	$cp_config = config_get_path("captiveportal/{$cpzone}/element", []);
	if (!is_array($cp_config)) {
		return;
	}
	usort($cp_config, static function ($a, $b) {
		return strcasecmp($a['name'] ?? '', $b['name'] ?? '');
	});
	config_set_path("captiveportal/{$cpzone}/element", $cp_config);
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function config_get_path(string $path, $default = null) {
	global $config;

	$parts = array_values(array_filter(explode('/', $path), 'strlen'));
	$cur = $config;
	foreach ($parts as $part) {
		if (!is_array($cur) || !array_key_exists($part, $cur)) {
			return $default;
		}
		$cur = $cur[$part];
	}
	return $cur;
}

function config_set_path(string $path, $value, $default = null) {
	global $config;

	if (!is_array($config)) {
		$config = array();
	}
	$append = str_ends_with($path, '/');
	$parts = array_values(array_filter(explode('/', $path), 'strlen'));
	if ($parts === array()) {
		return $default;
	}
	$cur =& $config;
	$last = array_pop($parts);
	foreach ($parts as $part) {
		if (!isset($cur[$part]) || !is_array($cur[$part])) {
			$cur[$part] = array();
		}
		$cur =& $cur[$part];
	}
	if ($append) {
		if (!isset($cur[$last]) || !is_array($cur[$last])) {
			$cur[$last] = array();
		}
		$cur[$last][] = $value;
	} else {
		$cur[$last] = $value;
	}
	return $value;
}
