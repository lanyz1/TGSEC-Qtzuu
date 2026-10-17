<?php
/* Lab stubs for pin excerpts. Nested config_get_path plus gettext. */

$g = array(
	'captiveportal_path' => '/lab/captiveportal',
	'captiveportal_element_path' => '/lab/cpelements',
	'captiveportal_element_sizelimit' => 1048576,
);

$config = array();
$cpzone = 'labzone';

function gettext($text) {
	return $text;
}

function g_get($key, $default = null) {
	global $g;
	if (array_key_exists($key, $g)) {
		return $g[$key];
	}
	return $default;
}

function lab_path_parts(string $path): array {
	$path = trim($path, '/');
	if ($path === '') {
		return array();
	}
	return explode('/', $path);
}

function config_get_path(string $path, $default = null) {
	global $config;
	if (!is_array($config)) {
		return $default;
	}
	$cur = $config;
	foreach (lab_path_parts($path) as $key) {
		if (!is_array($cur) || !array_key_exists($key, $cur)) {
			return $default;
		}
		$cur = $cur[$key];
	}
	return $cur;
}

function config_set_path(string $path, $value, $default = null) {
	global $config;
	if (!is_array($config)) {
		$config = array();
	}
	$keys = lab_path_parts($path);
	if ($keys === array()) {
		if (!is_array($value)) {
			return $default;
		}
		$config = $value;
		return $value;
	}
	$last = array_pop($keys);
	$cur = &$config;
	foreach ($keys as $key) {
		if (!isset($cur[$key]) || !is_array($cur[$key])) {
			$cur[$key] = array();
		}
		$cur = &$cur[$key];
	}
	$cur[$last] = $value;
	return $value;
}

function config_path_enabled(string $path, $enable_key = 'enable', $default = false) {
	$node = config_get_path($path, null);
	if (!is_array($node)) {
		return $default;
	}
	return array_key_exists($enable_key, $node) && $node[$enable_key] !== null;
}
