<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */
/* src/etc/inc/util.inc array_get_path */

/**
 * Return a value specified by a path of keys in a nested array, if it exists.
 *
 * @param array  $arr     Array to search
 * @param string $path    Path with '/' separators
 * @param mixed  $default Value to return if the path is not found
 *
 * @return mixed Value at path or $default if the path does not exist or if the
 *               path keys an empty string and $default is non-null
 */
function array_get_path(array &$arr, string $path, $default = null) {
	$vpath = explode('/', $path);
	$el = $arr;
	foreach ($vpath as $key) {
		if (mb_strlen($key) == 0) {
			continue;
		}
		if (is_array($el) && array_key_exists($key, $el)) {
			$el = $el[$key];
		} else {
			return ($default);
		}
	}

	if (($default !== null) && ($el === '')) {
		return ($default);
	}

	return ($el);
}
