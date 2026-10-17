<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

/* returns true if $ipaddr is a valid dotted IPv4 address or a IPv6
	false - not valid
	true (numeric 4 or 6) - if valid, gives type of address */
function is_ipaddr($ipaddr) {
	if (is_ipaddrv4($ipaddr)) {
		return 4;
	}
	if (is_ipaddrv6($ipaddr)) {
		return 6;
	}
	return false;
}

/* returns true if $ipaddr is a valid IPv6 address */
function is_ipaddrv6($ipaddr) {
	if (!is_string($ipaddr) || empty($ipaddr)) {
		return false;
	}
	/*
	 * While Net_IPv6::checkIPv6() considers IPv6/mask a valid IPv6,
	 * is_ipaddrv6() needs to be more strict to keep the compatibility
	 * with is_ipaddrv4().
	 */
	if (strstr($ipaddr, "/")) {
		return false;
	}
	if (strstr($ipaddr, "%") && is_linklocal($ipaddr)) {
		$tmpip = explode("%", $ipaddr);
		$ipaddr = $tmpip[0];
	}
	/*
	 * Net_IPv6::checkIPv6 does not reject multiple attempts at compression
	 * so we must check it beforehand.
	 * https://redmine.pfsense.org/issues/13069
	 */
	if (substr_count($ipaddr, '::') > 1) {
		return false;
	}
	/*
	 * Net_IPv6::checkIPv6 does not properly handle addresses with extra segments
	 * when compression is also used.
	 * https://redmine.pfsense.org/issues/16005
	 */
	try {
		return Net_IPv6::checkIPv6($ipaddr);
	} catch (\Throwable $th) {
		return false;
	}
}

/* returns true if $ipaddr is a valid dotted IPv4 address */
function is_ipaddrv4($ipaddr) {
	if (!is_string($ipaddr) || empty($ipaddr) || ip2long($ipaddr) === FALSE) {
		return false;
	}
	return true;
}

/* returns 4 or 6 respectively (== TRUE) if $ipaddr is a valid IPv4 or IPv6 linklocal address
   returns false if not a valid linklocal address */
function is_linklocal($ipaddr) {
	if (is_ipaddrv4($ipaddr)) {
		// input is IPv4
		// test if it's 169.254.x.x per rfc3927 2.1
		$ip4 = explode(".", $ipaddr);
		if ($ip4[0] == '169' && $ip4[1] == '254') {
			return 4;
		}
	} elseif (Net_IPv6::getAddressType($ipaddr) == NET_IPV6_LOCAL_LINK) {
		return 6;
	}
	return false;
}

function is_validaliasname($name, $return_message = false, $object = "alias") {
	/* Array of reserved words */
	$reserved = array("port", "pass");

	if (!is_string($name) || strlen($name) >= 32 || preg_match('/(^_*$|^\d*$|[^a-z0-9_])/i', $name)) {
		if ($return_message) {
			return sprintf(gettext('The %1$s name must be less than 32 characters long, may not consist of only numbers, may not consist of only underscores, and may only contain the following characters: %2$s'), $object, 'a-z, A-Z, 0-9, _');
		} else {
			return false;
		}
	}
	if (in_array($name, $reserved, true)) {
		if ($return_message) {
			return sprintf(gettext('The %1$s name must not be either of the reserved words %2$s or %3$s.'), $object, "'port'", "'pass'");
		} else {
			return false;
		}
	}
	if (getprotobyname($name)) {
		if ($return_message) {
			return sprintf(gettext('The %1$s name must not be an IP protocol name such as TCP, UDP, ICMP etc.'), $object);
		} else {
			return false;
		}
	}
	if (getservbyname($name, "tcp") || getservbyname($name, "udp")) {
		if ($return_message) {
			return sprintf(gettext('The %1$s name must not be a well-known or registered TCP or UDP port name such as ssh, smtp, pop3, tftp, http, openvpn etc.'), $object);
		} else {
			return false;
		}
	}
	if ($return_message) {
		return sprintf(gettext('The %1$s name is valid.'), $object);
	} else {
		return true;
	}
}
