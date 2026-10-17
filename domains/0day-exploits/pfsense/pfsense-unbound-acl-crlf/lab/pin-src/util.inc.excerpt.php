<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function is_ipaddr($ipaddr) {
	if (is_ipaddrv4($ipaddr)) {
		return 4;
	}
	if (is_ipaddrv6($ipaddr)) {
		return 6;
	}
	return false;
}

function is_ipaddrv6($ipaddr) {
	if (!is_string($ipaddr) || empty($ipaddr)) {
		return false;
	}
	if (strstr($ipaddr, "/")) {
		return false;
	}
	return filter_var($ipaddr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

function is_ipaddrv4($ipaddr) {
	if (!is_string($ipaddr) || empty($ipaddr) || ip2long($ipaddr) === FALSE) {
		return false;
	}
	return true;
}

function is_subnet($subnet) {
	if (is_string($subnet) && preg_match('/^(?:([0-9.]{7,15})|([0-9a-f:]{2,39}|[0-9a-f:]{2,30}[0-9.]{7,15}))\/(\d{1,3})$/i', $subnet, $parts)) {
		if (is_ipaddrv4($parts[1]) && $parts[3] <= 32) {
			return 4;
		}
		if (is_ipaddrv6($parts[2]) && $parts[3] <= 128) {
			return 6;
		}
	}
	return false;
}
