<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_igmpproxy_configure($interface='') {
	global $g;

	if (!empty($interface) && !empty(config_get_path('igmpproxy/igmpentry'))) {
		$igmpinf = "";
		foreach (config_get_path('igmpproxy/igmpentry', []) as $igmpentry) {
			if ($igmpentry['ifname'] == $interface) {
				$igmpinf = true;
				break;
			}
		}
		if (!$igmpinf) {
			return false;
		}
	}

	if (!config_path_enabled('igmpproxy')) {
		if (isvalidproc("igmpproxy")) {
			logger(LOG_INFO, localize_text("Stopping IGMP Proxy service."), LOG_PREFIX_IGMPPROXY);
			killbyname("igmpproxy");
		}
		return true;
	}
	if (count(config_get_path('igmpproxy/igmpentry', [])) == 0) {
		return false;
	}

	if (is_platform_booting()) {
		echo gettext("Starting IGMP Proxy service...");
	}

	if (isvalidproc("igmpproxy")) {
		logger(LOG_INFO, localize_text("Restarting IGMP Proxy service."), LOG_PREFIX_IGMPPROXY);
		killbyname("igmpproxy");
	}

	$iflist = get_configured_interface_list();

	$igmpconf = <<<EOD

##------------------------------------------------------
## Enable Quickleave mode (Sends Leave instantly)
##------------------------------------------------------
quickleave

EOD;

	foreach (config_get_path('igmpproxy/igmpentry', []) as $igmpcf) {
		if (empty(config_get_path("interfaces/{$igmpcf['ifname']}/ipaddr"))) {
			continue;
		}
		unset($iflist[$igmpcf['ifname']]);
		$realif = get_real_interface($igmpcf['ifname']);
		if (empty($igmpcf['threshold'])) {
			$threshld = 1;
		} else {
			$threshld = $igmpcf['threshold'];
		}
		$igmpconf .= "phyint {$realif} {$igmpcf['type']} ratelimit 0 threshold {$threshld}\n";

		if ($igmpcf['address'] <> "") {
			$item = explode(" ", $igmpcf['address']);
			foreach ($item as $iww) {
				$igmpconf .= "altnet {$iww}\n";
			}
		}
		$igmpconf .= "\n";
		if ($igmpcf['type'] == 'upstream') {
		       $upstream = true;
		} else {
		       $downstream = true;
		}
	}
	foreach ($iflist as $ifn) {
		$realif = get_real_interface($ifn);
		$igmpconf .= "phyint {$realif} disabled\n";
	}
	$igmpconf .= "\n";

	if (!$upstream || !$downstream) {
		logger(LOG_ERR, localize_text("Could not find upstream or downstream IGMP Proxy interfaces!"), LOG_PREFIX_IGMPPROXY);
		return;
	}

	$igmpfl = fopen(g_get('varetc_path') . "/igmpproxy.conf", "w");
	if (!$igmpfl) {
		logger(LOG_ERR, localize_text("Could not write IGMP Proxy configuration file!"), LOG_PREFIX_IGMPPROXY);
		return;
	}
	fwrite($igmpfl, $igmpconf);
	fclose($igmpfl);
	unset($igmpconf);

	if (config_path_enabled('syslog','igmpxverbose')) {
		mwexec_bg("/usr/local/sbin/igmpproxy -v {$g['varetc_path']}/igmpproxy.conf");
	} else {
		mwexec_bg("/usr/local/sbin/igmpproxy {$g['varetc_path']}/igmpproxy.conf");
	}

	logger(LOG_INFO, localize_text("Started IGMP Proxy service."), LOG_PREFIX_IGMPPROXY);

	if (is_platform_booting()) {
		echo gettext("done.") . "\n";
	}

	return true;
}
