<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_igmpproxy_edit_save_from_post() {
	global $input_errors, $pconfig, $id, $this_igmpproxy_config;

if ($_POST['save']) {
	unset($input_errors);
	$pconfig = $_POST;

	if ($_POST['type'] == "upstream") {
		foreach (config_get_path('igmpproxy/igmpentry', []) as $pid => $proxyentry) {
			if (isset($id) && $id == $pid) {
				continue;
			}

			if ($proxyentry['type'] == "upstream" && $proxyentry['ifname'] != $_POST['interface']) {
				$input_errors[] = gettext("Only one 'upstream' interface can be configured.");
			}
		}
	}

	if (!empty($_POST['threshold']) && (!is_numeric($_POST['threshold']) ||
	    ($_POST['threshold'] < -1) || ($_POST['threshold'] > 256))) {
		$input_errors[] = gettext("Threshold value should be between -1 and 256.");
	} 

	$igmpentry = array();
	$igmpentry['ifname'] = $_POST['ifname'];
	$igmpentry['threshold'] = $_POST['threshold'];
	$igmpentry['type'] = $_POST['type'];
	$address = "";
	$isfirst = 0;

	/* item is a normal igmpentry type */
	$x = 0;
	while ($_POST["address{$x}"]) {

		if ($isfirst > 0) {
			$address .= " ";
		}

		$this_addr =  $_POST["address{$x}"] . "/" . $_POST["address_subnet{$x}"];
		if (is_subnetv4($this_addr)) {
			$address .= $this_addr;
			$isfirst++;
		} else {
			$input_errors[] = sprintf(gettext("The following submitted address is invalid: %s"), $this_addr);
		}

		$x++;
	}

	if (!$input_errors) {
		$igmpentry['address'] = $address;
		$igmpentry['descr'] = $_POST['descr'];

		if ($this_igmpproxy_config) {
			config_set_path("igmpproxy/igmpentry/{$id}", $igmpentry);
		} else {
			config_set_path('igmpproxy/igmpentry/', $igmpentry);
		}

		write_config("IGMP Proxy item saved");

		mark_subsystem_dirty('igmpproxy');
	} else {
		//we received input errors, copy data to prevent retype
		$pconfig['descr'] = $_POST['descr'];
		$pconfig['address'] = $address;
		$pconfig['type'] = $_POST['type'];
	}
}

	return is_array($input_errors) ? $input_errors : array();
}

/*
 * UI-only type select from services_igmpproxy_edit.php. POST is not enum-checked.
 * $section->addInput(new Form_Select(
 *	'type',
 *	'*Type',
 *	$pconfig['type'],
 *	['upstream' => gettext('Upstream Interface'), 'downstream' => gettext('Downstream Interface')]
 * ));
 */
