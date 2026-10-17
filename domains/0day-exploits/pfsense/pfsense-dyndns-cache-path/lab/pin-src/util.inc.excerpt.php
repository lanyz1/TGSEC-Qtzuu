<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function is_domain($domain, $allow_wildcard=false, $trailing_dot=true) {
	if (!is_string($domain)) {
		return false;
	}
	if (!$trailing_dot && ($domain[strlen($domain)-1] == ".")) {
		return false;
	}
	if ($allow_wildcard) {
		$domain_regex = '/^(?:(?:[a-z_0-9\*]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$/i';
	} else {
		$domain_regex = '/^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$/i';
	}

	if (preg_match($domain_regex, $domain)) {
		return true;
	} else {
		return false;
	}
}
