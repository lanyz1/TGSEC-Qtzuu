<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function get_vlan_tag_types() {
	return [
		'ctag' => 'C-Tag (0x8100)',
		'stag' => 'S-Tag (0x88A8)'
	];
}

function vlan_edit_build_portlist() {
	$portlist = get_interface_list();
	$lagglist = get_lagg_interface_list();
	$portlist = array_merge($portlist, $lagglist);
	foreach ($lagglist as $lagg) {
		/* LAGG members cannot be assigned */
		$laggmembers = explode(',', $lagg['members']);
		foreach ($laggmembers as $lagm) {
			if (isset($portlist[$lagm])) {
				unset($portlist[$lagm]);
			}
		}
	}

	/* Do not allow OpenVPN TUN interfaces to be used for QinQ
	 * https://redmine.pfsense.org/issues/11675 */
	foreach ($portlist as $portname => $port) {
		if (strstr($portname, "ovpn")) {
			preg_match('/ovpn([cs])([1-9]+)/', $portname, $m);
			$type = ($m[1] == 'c') ? 'client' : 'server';
			foreach (config_get_path("openvpn/openvpn-{$type}", []) as $ovpn) {
				if (($ovpn['vpnid'] == $m[2]) && ($ovpn['dev_mode'] == 'tun')) {
					unset($portlist[$portname]);
				}
			}
		}
	}
	return $portlist;
}

function vlan_edit_save() {
	global $id, $this_vlan_config, $input_errors, $portlist, $confif;

	$input_errors = array();
	$confif = '';

	/*
	 * Check user privileges to test if the user is allowed to make changes.
	 * Otherwise users can end up in an inconsistent state where some changes are
	 * performed and others denied. See https://redmine.pfsense.org/issues/15282
	 */

	/* input validation */
	$reqdfields = explode(" ", "if tag");
	$reqdfieldsn = array(gettext("Parent interface"), gettext("VLAN tag"));

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if (isset($_POST['tag']) && !vlan_valid_tag($_POST['tag'])) {
		$input_errors[] = gettext("The VLAN tag must be an integer between 1 and 4094.");
	}
	if (isset($_POST['pcp']) && !empty($_POST['pcp']) && (!is_numericint($_POST['pcp']) || ($_POST['pcp'] < '0') || ($_POST['pcp'] > '7'))) {
		$input_errors[] = gettext("The VLAN Priority must be an integer between 0 and 7.");
 	}

	if (!does_interface_exist($_POST['if'])) {
		$input_errors[] = gettext("Interface supplied as parent is invalid");
	}

	if (!array_key_exists($_POST['tag_type'], get_vlan_tag_types())) {
		$input_errors[] = gettext("The selected VLAN Tag Type is invalid.");
	}

	if (isset($id)) {
		if ($_POST['tag'] && $_POST['tag'] != $this_vlan_config['tag']) {
			if (!empty($this_vlan_config['vlanif']) && convert_real_interface_to_friendly_interface_name($this_vlan_config['vlanif']) != NULL) {
				$input_errors[] = gettext("The VLAN tag cannot be changed while the interface is assigned.");
			}
		}
	}
	foreach (config_get_path('vlans/vlan', []) as $vlan) {
		if ($this_vlan_config && ($this_vlan_config === $vlan)) {
			continue;
		}

		if (($vlan['if'] == $_POST['if']) && ($vlan['tag'] == $_POST['tag'])) {
			$input_errors[] = sprintf(gettext("A VLAN with the tag %s is already defined on this interface."), $vlan['tag']);
			break;
		}
	}

	foreach (config_get_path('qinqs/qinqentry', []) as $qinq) {
		if ($qinq['tag'] == $_POST['tag'] && $qinq['if'] == $_POST['if']) {
			$input_errors[] = sprintf(gettext('A QinQ VLAN exists on %s with this tag. Please remove it to use this tag for a normal VLAN.'), $_POST['if']);
		}
	}

	if (!$input_errors) {
		if ($this_vlan_config) {
			if (($this_vlan_config['if'] != $_POST['if']) || ($this_vlan_config['tag'] != $_POST['tag'])) {
				if (!empty($this_vlan_config['vlanif'])) {
					$confif = convert_real_interface_to_friendly_interface_name($this_vlan_config['vlanif']);
					// Destroy previous vlan
					pfSense_interface_destroy($this_vlan_config['vlanif']);
				} else {
					pfSense_interface_destroy(vlan_interface($this_vlan_config));
					$confif = convert_real_interface_to_friendly_interface_name(vlan_interface($this_vlan_config));
				}
				if ($confif != "") {
					config_set_path("interfaces/{$confif}/if", vlan_interface($_POST));
				}
			}
		}
		$vlan = array();
		$vlan['if'] = $_POST['if'];
		$vlan['tag_type'] = $_POST['tag_type'];
		$vlan['tag'] = $_POST['tag'];
		$vlan['pcp'] = $_POST['pcp'];
		$vlan['descr'] = $_POST['descr'];
		$vlan['vlanif'] = vlan_interface($_POST);
		$vlanif = interface_vlan_configure($vlan);
		if ($vlanif == NULL || $vlanif != $vlan['vlanif']) {
			pfSense_interface_destroy($vlan['vlanif']);
			$input_errors[] = gettext("Error occurred creating interface, please retry.");
		} else {
			if ($this_vlan_config) {
				config_set_path("vlans/vlan/{$id}", $vlan);
			} else {
				config_set_path('vlans/vlan/', $vlan);
			}

			write_config("VLAN interface added");

			if ($confif != "") {
				interface_configure($confif);
			}
		}
		$GLOBALS['lab_vlan'] = $vlan;
		$GLOBALS['lab_vlanif'] = $vlanif;
	}
}
