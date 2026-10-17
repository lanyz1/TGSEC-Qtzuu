<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function interfaces_page_get($if) {
	$ifdescrs = get_configured_interface_with_descr(true);
	if (empty($ifdescrs[$if])) {
		return array(
			'redirect' => true,
			'if' => $if,
		);
	}

	$wancfg = config_get_path("interfaces/{$if}", []);
	$wlanif = null;
	$clone_ok = null;
	$wl_modes = array();
	$wlanbaseif = null;

	/* Wireless interface? */
	if (is_array(array_get_path($wancfg, 'wireless'))) {
		/* Sync first to be sure it displays the actual settings that will be used */
		interface_sync_wireless_clones($wancfg, false);
		/* Get wireless modes */
		$wlanif = get_real_interface($if);
		if (!does_interface_exist($wlanif)) {
			$clone_ok = interface_wireless_clone($wlanif, $wancfg);
		}
		$wlanbaseif = interface_get_wireless_base(array_get_path($wancfg, 'if'));
		$wl_modes = get_wireless_modes($if);
	}

	return array(
		'redirect' => false,
		'if' => $if,
		'wancfg' => $wancfg,
		'wlanif' => $wlanif,
		'wlanbaseif' => $wlanbaseif,
		'clone_ok' => $clone_ok,
		'wl_modes' => $wl_modes,
	);
}
