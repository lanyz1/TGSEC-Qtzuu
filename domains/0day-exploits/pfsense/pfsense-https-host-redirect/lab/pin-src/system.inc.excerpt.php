<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */
/* src/etc/inc/system.inc:2294-2306 HTTP-to-HTTPS nginx server{}. */

function system_generate_nginx_http_https_redirect($captive_portal, $nginx_port) {
	$nginx_config = '';

	// Add HTTP to HTTPS redirect
	if ($captive_portal === false && config_get_path('system/webgui/protocol') == "https" && !(config_path_enabled('system/webgui', 'disablehttpredirect') != null)) {
		if ($nginx_port != "443") {
			$redirectport = ":{$nginx_port}";
		}
		$nginx_config .= <<<EOD
	server {
		listen 80;
		listen [::]:80;
		return 301 https://\$http_host$redirectport\$request_uri;
	}

EOD;
	}

	return $nginx_config;
}
