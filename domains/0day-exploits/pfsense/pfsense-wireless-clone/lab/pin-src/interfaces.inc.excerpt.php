<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function interface_wireless_clone($realif, $wlcfg) {
	global $g;
	/*   Check to see if interface has been cloned as of yet.
	 *   If it has not been cloned then go ahead and clone it.
	 */
	$needs_clone = false;
	if (is_array($wlcfg['wireless'])) {
		$wlcfg_mode = $wlcfg['wireless']['mode'];
	} else {
		$wlcfg_mode = $wlcfg['mode'];
	}
	switch ($wlcfg_mode) {
		case "hostap":
			$mode = "wlanmode hostap";
			break;
		case "adhoc":
			$mode = "wlanmode adhoc";
			break;
		default:
			$mode = "";
			break;
	}
	$baseif = interface_get_wireless_base($wlcfg['if']);
	if (does_interface_exist($realif)) {
		exec("/sbin/ifconfig " . escapeshellarg($realif), $output, $ret);
		$ifconfig_str = implode($output);
		if (($wlcfg_mode == "hostap") && (!preg_match("/hostap/si", $ifconfig_str))) {
			logger(LOG_INFO, localize_text("Interface %s changed to hostap mode", $realif));
			$needs_clone = true;
		}
		if (($wlcfg_mode == "adhoc") && (!preg_match("/adhoc/si", $ifconfig_str))) {
			logger(LOG_INFO, localize_text("Interface %s changed to adhoc mode", $realif));
			$needs_clone = true;
		}
		if (($wlcfg_mode == "bss") && (preg_match("/hostap|adhoc/si", $ifconfig_str))) {
			logger(LOG_INFO, localize_text("Interface %s changed to infrastructure mode", $realif));
			$needs_clone = true;
		}
	} else {
		$needs_clone = true;
	}

	if ($needs_clone == true) {
		/* remove previous instance if it exists */
		if (does_interface_exist($realif)) {
			pfSense_interface_destroy($realif);

			/* Invalidate cache */
			get_interface_arr(true);
		}

		logger(LOG_INFO, localize_text("Cloning new wireless interface %s", $realif));
		// Create the new wlan interface. FreeBSD returns the new interface name.
		// example:  wlan2
		exec("/sbin/ifconfig wlan create wlandev {$baseif} {$mode} bssid 2>&1", $out, $ret);
		if ($ret <> 0) {
			logger(LOG_ERR, localize_text('Failed to clone interface %1$s with error code %2$s, output %3$s', $baseif, $ret, $out[0]));
			return false;
		}
		$newif = trim($out[0]);
		// Rename the interface to {$parentnic}_wlan{$number}#: EX: ath0_wlan0
		pfSense_interface_rename($newif, $realif);
		file_put_contents("{$g['tmp_path']}/{$realif}_oldmac", get_interface_mac($realif));
	}
	return true;
}

function interface_get_wireless_base($wlif) {
	if (!stristr($wlif, "_wlan")) {
		return $wlif;
	} else {
		return substr($wlif, 0, stripos($wlif, "_wlan"));
	}
}
