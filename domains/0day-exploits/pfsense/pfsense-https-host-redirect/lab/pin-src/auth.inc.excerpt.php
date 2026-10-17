<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */
/* src/etc/inc/auth.inc:77-145 PHP DNS-rebind. Does not run on the nginx 301. */

function lab_dns_rebind_check() {
	$found_host = false;
	$blocked = false;
	$message = '';
	$status = 0;

	if (function_exists("display_error_form") && !config_path_enabled('system/webgui', 'nodnsrebindcheck')) {
		/* DNS ReBinding attack prevention.  https://redmine.pfsense.org/issues/708 */
		$found_host = false;

		/* Either a IPv6 address with or without a alternate port */
		if (strstr($_SERVER['HTTP_HOST'], "]")) {
			$http_host_port = explode("]", $_SERVER['HTTP_HOST']);
			/* v6 address has more parts, drop the last part */
			if (count($http_host_port) > 1) {
				array_pop($http_host_port);
				$http_host = str_replace(array("[", "]"), "", implode(":", $http_host_port));
			} else {
				$http_host = str_replace(array("[", "]"), "", implode(":", $http_host_port));
			}
		} else {
			$http_host = explode(":", $_SERVER['HTTP_HOST']);
			$http_host = $http_host[0];
		}
		if (is_ipaddr($http_host) or $_SERVER['SERVER_ADDR'] == "127.0.0.1" or
			strcasecmp($http_host, "localhost") == 0 or $_SERVER['SERVER_ADDR'] == "::1") {
			$found_host = true;
		}
		if (strcasecmp($http_host, config_get_path('system/hostname') . "." . config_get_path('system/domain')) == 0 or
			strcasecmp($http_host, config_get_path('system/hostname')) == 0) {
			$found_host = true;
		}

		if (!$found_host) {
			foreach (config_get_path('dyndnses/dyndns', []) as $dyndns) {
				if (!is_array($dyndns) || empty($dyndns)) {
					continue;
				}
				if (strcasecmp($dyndns['host'], $http_host) == 0) {
					$found_host = true;
					break;
				}
			}
		}

		if (!$found_host) {
			foreach (config_get_path('dnsupdates/dnsupdate', []) as $rfc2136) {
				if (!is_array($rfc2136) || empty($rfc2136)) {
					continue;
				}
				if (strcasecmp($rfc2136['host'], $http_host) == 0) {
					$found_host = true;
					break;
				}
			}
		}

		if (!$found_host) {
			$althosts = explode(" ", config_get_path('system/webgui/althostnames', ""));
			foreach ($althosts as $ah) {
				if (strcasecmp($ah, $http_host) == 0 or strcasecmp($ah, $_SERVER['SERVER_ADDR']) == 0) {
					$found_host = true;
					break;
				}
			}
		}

		if ($found_host == false) {
			if (!security_checks_disabled()) {
				display_error_form("501", gettext("Potential DNS Rebind attack detected, see https://en.wikipedia.org/wiki/DNS_rebinding<br />Try accessing the router by IP address instead of by hostname."));
				$blocked = true;
				$status = 501;
				$message = $GLOBALS['lab_error_form']['message'] ?? '';
			}
		}
	}

	return array(
		'found_host' => $found_host,
		'blocked' => $blocked,
		'status' => $status,
		'message' => $message,
		'http_host' => $_SERVER['HTTP_HOST'] ?? '',
		'server_addr' => $_SERVER['SERVER_ADDR'] ?? '',
	);
}
