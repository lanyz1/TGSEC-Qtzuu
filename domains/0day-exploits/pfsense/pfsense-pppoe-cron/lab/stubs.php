<?php
/* Lab stubs for pin excerpts. Nested config_get_path/set_path for cron/item. */

global $config;
$config = array(
	'cron' => array(
		'item' => array(),
	),
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

function logger($priority, $message, $prefix = null, $facilities = null) {
	$GLOBALS['lab_logs'][] = array(
		'priority' => $priority,
		'message' => $message,
	);
}

function log_invalid_config_path($path) {
	logger(LOG_WARNING, "config warning: invalid path \"{$path}\"");
}

function is_process_running($name) {
	return true;
}

function sigkillbypid($pidfile, $sig, $waitfor = 0) {
	return 0;
}

if (!function_exists('mb_strlen')) {
	function mb_strlen($string, $encoding = null) {
		return strlen($string);
	}
}

function config_get_path(string $path, $default = null) {
	global $config;
	if (str_ends_with(trim($path), '/') || str_contains($path, '//')) {
		log_invalid_config_path($path);
		return $default;
	}
	if (!is_array($config)) {
		return $default;
	}
	$el = $config;
	foreach (explode('/', $path) as $key) {
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
	if (str_contains($path, '//')) {
		log_invalid_config_path($path);
		return $default;
	}
	if (!is_array($config)) {
		$config = array();
	}
	$append = ($path !== '' && str_ends_with($path, '/'));
	$parts = array();
	foreach (explode('/', $path) as $key) {
		if ($key !== '') {
			$parts[] = $key;
		}
	}
	if (count($parts) === 0) {
		return $default;
	}
	$el = &$config;
	$leaf = array_pop($parts);
	foreach ($parts as $key) {
		if (!isset($el[$key]) || !is_array($el[$key])) {
			$el[$key] = array();
		}
		$el = &$el[$key];
	}
	if ($append) {
		if (!isset($el[$leaf]) || !is_array($el[$leaf])) {
			$el[$leaf] = array();
		}
		$el[$leaf][] = $value;
	} else {
		$el[$leaf] = $value;
	}
	return $value;
}

function config_del_path(string $path, $default = null) {
	global $config;
	if (str_ends_with(trim($path), '/') || str_contains($path, '//')) {
		log_invalid_config_path($path);
		return $default;
	}
	if (!is_array($config)) {
		return $default;
	}
	$parts = array();
	foreach (explode('/', $path) as $key) {
		if ($key !== '') {
			$parts[] = $key;
		}
	}
	if (count($parts) === 0) {
		return $default;
	}
	$el = &$config;
	$leaf = array_pop($parts);
	foreach ($parts as $key) {
		if (!is_array($el) || !array_key_exists($key, $el)) {
			return $default;
		}
		$el = &$el[$key];
	}
	if (!is_array($el) || !array_key_exists($leaf, $el)) {
		return $default;
	}
	$ret = $el[$leaf];
	unset($el[$leaf]);
	return $ret;
}
