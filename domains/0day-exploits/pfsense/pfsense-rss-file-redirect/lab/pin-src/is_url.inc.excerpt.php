<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

/****f* util/is_URL
 * NAME
 *   is_URL
 * INPUTS
 *   $url: string to check
 *   $httponly: Only allow HTTP or HTTPS scheme
 * RESULT
 *   Returns true if item is a URL
 ******/
function is_URL($url, $httponly = false) {
	if (filter_var($url, FILTER_VALIDATE_URL)) {
		if ($httponly) {
			return in_array(strtolower(parse_url($url, PHP_URL_SCHEME)), ['http', 'https']);
		}
		return true;
	}
	return false;
}
