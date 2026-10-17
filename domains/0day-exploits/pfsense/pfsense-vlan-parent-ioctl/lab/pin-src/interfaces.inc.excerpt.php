<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function vlan_valid_tag($tag = NULL) {

	if ($tag == NULL || empty($tag) ||
	    !is_numericint($tag) || intval($tag) < 1 || intval($tag) > 4094) {
		return (false);
	}
	return (true);
}
function vlan_interface($vlan = NULL) {
	if ($vlan == NULL || !is_array($vlan) || !isset($vlan['if']) ||
	    !isset($vlan['tag']) || !vlan_valid_tag($vlan['tag'])) {
		return (NULL);
	}
	return ("{$vlan['if']}.{$vlan['tag']}");
}
function interface_vlan_set_tag_type(string $interface, string $tag_type): void {
	$command = [
		'/sbin/ifconfig',
		escapeshellarg($interface),
		'vlanproto',
		(($tag_type == 'stag') ? '802.1ad' : '802.1q'),
		'>',
		'/dev/null',
		'2>&1'
	];
	mwexec(implode(' ', $command));
}
function interface_vlan_configure(&$vlan, $flush = true, $skip_parent_mtu = false) {
	if (!is_array($vlan)) {
		logger(LOG_DEBUG, localize_text("%s called with wrong options. Problems with config!", 'interface_vlan_configure'));
		return(NULL);
	}
	$if = $vlan['if'];
	if (empty($if)) {
		logger(LOG_DEBUG, localize_text("%s called with if undefined.", 'interface_vlan_configure'));
		return(NULL);
	}

	$vlanif = empty($vlan['vlanif']) ? vlan_interface($vlan) : $vlan['vlanif'];
	if ($vlanif == NULL) {
		logger(LOG_DEBUG, localize_text("%s called with if undefined var.", 'vlan_interface'));
		return(NULL);
	}
	$tag = $vlan['tag'];
	$pcp  = empty($vlan['pcp']) ? 0 : $vlan['pcp'];	/* Apply "Best Effort" if not set */

	/* make sure the parent interface is up */
	interfaces_bring_up($if);
	/* Since we are going to add vlan(4) try to enable all that hardware supports. */
	pfSense_interface_capabilities($if, IFCAP_VLAN_HWTAGGING|IFCAP_VLAN_MTU|IFCAP_VLAN_HWFILTER);

	if (!empty($vlanif) && does_interface_exist($vlanif)) {
		pfSense_interface_destroy($vlanif);
	}

	$tmpvlanif = pfSense_interface_create2("vlan");
	if (!is_string($tmpvlanif)) {
		logger(LOG_ERR, localize_text('Failed to configure interface %1$s: Could not create temporary interface %2$s', $vlan['vlanif'], 'vlan'));
		return(NULL);
	}
	pfSense_interface_rename($tmpvlanif, $vlanif);
	pfSense_ngctl_name("{$tmpvlanif}:", $vlanif);

	pfSense_vlan_create($vlanif, $if, $tag, $pcp);

	interfaces_bring_up($vlanif);

	/* invalidate interface cache */
	if ($flush) {
		get_interface_arr(true);
	}

	/* configure interface if assigned */
	$assignedif = convert_real_interface_to_friendly_interface_name($vlanif);
	if ($assignedif) {
		if (config_path_enabled("interfaces/{$assignedif}")) {
			interface_configure($assignedif, true, false, $skip_parent_mtu);
		}
	}

	/* XXX: ermal -- for now leave it here at the moment it does not hurt. */
	interfaces_bring_up($if);

	if (interface_vlan_mtu_configured($vlanif)) {
		set_interface_mtu($vlanif, interface_vlan_mtu_configured($vlanif));
	}

	$tag_type = match ($vlan['tag_type']) {
		'ctag' => 'ctag',
		'stag' => 'stag',
		default => 'ctag'
	};
	interface_vlan_set_tag_type($vlanif, $tag_type);

	return $vlanif;
}
