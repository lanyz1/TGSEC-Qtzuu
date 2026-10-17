<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function compare_interface_friendly_names($a, $b) {
	if ($a == $b) {
		return 0;
	} else if ($a == 'wan') {
		return -1;
	} else if ($b == 'wan') {
		return 1;
	} else if ($a == 'lan') {
		return -1;
	} else if ($b == 'lan') {
		return 1;
	}

	return strnatcmp($a, $b);
}

function get_configured_interface_list(bool $with_disabled = false) : array
{
	$iflist = [];
	foreach (config_get_path('interfaces', []) as $if => $if_detail) {
		if ($with_disabled || isset($if_detail['enable'])) {
			$iflist[$if] = $if;
		}
	}

	return ($iflist);
}

function get_configured_interface_with_descr(bool $with_disabled = false) : array
{
	$iflist = [];
	foreach (config_get_path('interfaces', []) as $if => $if_detail) {
		if ($with_disabled || isset($if_detail['enable'])) {
			$iflist[$if] = strtoupper(array_get_path($if_detail, 'descr', $if));
		}
	}

	return ($iflist);
}

function array_get_path(array &$arr, string $path, $default = null) {
	$vpath = explode('/', $path);
	$el = $arr;
	foreach ($vpath as $key) {
		if (strlen($key) == 0) {
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
