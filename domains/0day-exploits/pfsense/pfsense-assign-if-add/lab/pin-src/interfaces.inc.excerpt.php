<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function convert_real_interface_to_friendly_interface_name($interface = "wan", $checkparent = false) {

	/* XXX: For speed reasons reference directly the interface array */
	$ifdescrs = config_get_path('interfaces', []);
	//$ifdescrs = get_configured_interface_list(true);

	foreach ($ifdescrs as $if => $ifname) {
		if ($if == $interface || $ifname['if'] == $interface) {
			return $if;
		}

		if (get_real_interface($if) == $interface) {
			return $if;
		}

		if ($checkparent == false) {
			continue;
		}
	}
}

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

function interface_sync_wireless_clones(&$ifcfg, $sync_changes = false) {

	$shared_settings = array('standard', 'turbo', 'protmode', 'txpower', 'channel',
				 'diversity', 'txantenna', 'rxantenna', 'distance',
				 'regdomain', 'regcountry', 'reglocation');

	if (!is_interface_wireless($ifcfg['if'])) {
		return;
	}

	$baseif = interface_get_wireless_base($ifcfg['if']);

	// Sync shared settings for assigned clones
	$iflist = get_configured_interface_list(true);
	foreach ($iflist as $if) {
		if (($baseif == interface_get_wireless_base(config_get_path("interfaces/{$if}/if"))) &&
			($ifcfg['if'] != config_get_path("interfaces/{$if}/if"))) {
			if (config_path_enabled("interfaces/{$if}/wireless", 'standard') || $sync_changes) {
				foreach ($shared_settings as $setting) {
					if ($sync_changes) {
						if (isset($ifcfg['wireless'][$setting])) {
							config_set_path("interfaces/{$if}/wireless/{$setting}",
											$ifcfg['wireless'][$setting]);
						} elseif (!empty(config_get_path("interfaces/{$if}/wireless/{$setting}"))) {
							config_del_path("interfaces/{$if}/wireless/{$setting}");
						}
					} else {
						if (!empty(config_get_path("interfaces/{$if}/wireless/{$setting}"))) {
							$ifcfg['wireless'][$setting] =
							    config_get_path("interfaces/{$if}/wireless/{$setting}");
						} elseif (isset($ifcfg['wireless'][$setting])) {
							unset($ifcfg['wireless'][$setting]);
						}
					}
				}
				if (!$sync_changes) {
					break;
				}
			}
		}
	}

	// Read or write settings at shared area
	if (!empty(config_get_path("wireless/interfaces/{$baseif}"))) {
		foreach ($shared_settings as $setting) {
			if ($sync_changes) {
				if (isset($ifcfg['wireless'][$setting])) {
					config_set_path("wireless/interfaces/{$baseif}/{$setting}",
									$ifcfg['wireless'][$setting]);
				} elseif (!empty(config_get_path("wireless/interfaces/{$baseif}/{$setting}"))) {
					config_del_path("wireless/interfaces/{$baseif}/{$setting}");
				}
			} else {
				if (!empty(config_get_path("wireless/interfaces/{$baseif}/{$setting}"))) {
					$ifcfg['wireless'][$setting] = config_get_path("wireless/interfaces/{$baseif}/{$setting}");
				} elseif (isset($ifcfg['wireless'][$setting])) {
					unset($ifcfg['wireless'][$setting]);
				}
			}
		}
	}

	// Sync the mode on the clone creation page with the configured mode on the interface
	if (interface_is_wireless_clone($ifcfg['if'])) {
		foreach (config_get_path('wireless/clone', []) as $key => $clone) {
			if ($clone['cloneif'] == $ifcfg['if']) {
				if ($sync_changes) {
					config_set_path("wireless/clone/{$key}/mode", $ifcfg['wireless']['mode']);
				} else {
					$ifcfg['wireless']['mode'] = $clone['mode'];
				}
				break;
			}
		}
		unset($clone);
	}
}

function interface_is_wireless_clone($wlif) {
	if (!stristr($wlif, "_wlan")) {
		return false;
	} else {
		return true;
	}
}

function interface_get_wireless_base($wlif) {
	if (!stristr($wlif, "_wlan")) {
		return $wlif;
	} else {
		return substr($wlif, 0, stripos($wlif, "_wlan"));
	}
}

function interface_get_wireless_clone($wlif) {
	if (!stristr($wlif, "_wlan")) {
		return $wlif . "_wlan0";
	} else {
		return $wlif;
	}
}

function get_real_interface($interface = "wan", $family = "all", $realv6iface = false, $flush = false) {
	global $g;

	if (empty($interface)) {
		return null;
	}

	$wanif = NULL;

	switch ($interface) {
		case "l2tp":
			$wanif = "l2tp";
			break;
		case "pptp":
			$wanif = "pptp";
			break;
		case "pppoe":
			$wanif = "pppoe";
			break;
		case "openvpn":
			$wanif = "openvpn";
			break;
		case "IPsec":
		case "ipsec":
		case "enc0":
			$wanif = "enc0";
			break;
		case "ppp":
			$wanif = "ppp";
			break;
		default:
			if (substr($interface, 0, 4) == '_vip') {
				$wanif = $interface;
				break;
			} elseif (substr($interface, 0, 5) == '_lloc') {
				$interface = substr($interface, 5);
			} elseif (interface_is_vlan($interface) != NULL ||
			    does_interface_exist($interface, $flush)) {
				/*
				 * If a real interface was already passed simply
				 * pass the real interface back.  This encourages
				 * the usage of this function in more cases so that
				 * we can combine logic for more flexibility.
				 */
				$wanif = $interface;
				break;
			}

			$cfg = config_get_path("interfaces/{$interface}");
			if (empty($cfg))
				break;

			if ($family == "inet6") {
				if (is_array($cfg['wireless']) || preg_match(g_get('wireless_regex'), $cfg['if'])) {
					$wanif = interface_get_wireless_clone($cfg['if']);
				} else {
					$wanif = $cfg['if'];
				}
			} else {
				// Wireless cloned NIC support (FreeBSD 8+)
				// interface name format: $parentnic_wlanparentnic#
				// example: ath0_wlan0
				if (is_array($cfg['wireless']) || preg_match(g_get('wireless_regex'), $cfg['if'])) {
					$wanif = interface_get_wireless_clone($cfg['if']);
				} else {
					$wanif = $cfg['if'];
				}
			}
			break;
	}

	return $wanif;
}

function is_interface_wireless($interface) {
	global $g;

	$friendly = convert_real_interface_to_friendly_interface_name($interface);
	if (!empty($friendly) && config_get_path("interfaces/{$friendly}/wireless") === null) {
		if (preg_match(g_get('wireless_regex'), $interface)) {
			config_init_path("interfaces/{$friendly}/wireless");
			return true;
		}
		return false;
	} else {
		return true;
	}
}

function get_wireless_modes($interface) {
	/* return wireless modes and channels */
	$wireless_modes = array();

	$cloned_interface = get_real_interface($interface);

	if ($cloned_interface && is_interface_wireless($cloned_interface)) {
		$chan_list = "/sbin/ifconfig {$cloned_interface} list chan";
		$stack_list = "/usr/bin/awk -F\"Channel \" '{ gsub(/\\*/, \" \"); print \$2 \"\\n\" \$3 }'";
		$format_list = "/usr/bin/awk '{print \$5 \" \" \$6 \",\" \$1}'";

		$interface_channels = [];
		exec("$chan_list | $stack_list | /usr/bin/sort -u | $format_list 2>&1", $interface_channels);
		$interface_channel_count = count($interface_channels);

		$c = 0;
		while ($c < $interface_channel_count) {
			$channel_line = explode(",", $interface_channels["$c"]);
			$wireless_mode = trim($channel_line[0]);
			$wireless_channel = trim($channel_line[1]);
			if (trim($wireless_mode) != "") {
				/* if we only have 11g also set 11b channels */
				if ($wireless_mode == "11g") {
					if (!isset($wireless_modes["11b"])) {
						$wireless_modes["11b"] = array();
					}
				} elseif ($wireless_mode == "11g ht") {
					if (!isset($wireless_modes["11b"])) {
						$wireless_modes["11b"] = array();
					}
					if (!isset($wireless_modes["11g"])) {
						$wireless_modes["11g"] = array();
					}
					$wireless_mode = "11ng";
				} elseif ($wireless_mode == "11a ht") {
					if (!isset($wireless_modes["11a"])) {
						$wireless_modes["11a"] = array();
					}
					$wireless_mode = "11na";
				}
				$wireless_modes["$wireless_mode"]["$c"] = $wireless_channel;
			}
			$c++;
		}
	}
	return($wireless_modes);
}
