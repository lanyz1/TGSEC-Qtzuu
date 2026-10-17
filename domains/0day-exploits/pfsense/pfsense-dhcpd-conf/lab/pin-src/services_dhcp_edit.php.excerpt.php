<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_dhcp_edit_save_from_post() {
	global $input_errors, $pconfig, $if, $id, $this_map_config;

	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	$reqdfields = array();
	$reqdfieldsn = array();

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	/* either MAC or Client-ID must be specified */
	if (empty($_POST['mac']) && empty($_POST['cid'])) {
		$input_errors[] = gettext("Either MAC address or Client identifier must be specified");
	}

	/* normalize MAC addresses - lowercase and convert Windows-ized hyphenated MACs to colon delimited */
	$_POST['mac'] = trim(strtolower(str_replace("-", ":", $_POST['mac'])));

	if ($_POST['hostname']) {
		preg_match("/\-\$/", $_POST['hostname'], $matches);
		if ($matches) {
			$input_errors[] = gettext("The hostname cannot end with a hyphen according to RFC952");
		}
		if (!is_hostname($_POST['hostname'])) {
			$input_errors[] = gettext("The hostname can only contain the characters A-Z, 0-9 and '-'.");
		} else {
			if (!is_unqualified_hostname($_POST['hostname'])) {
				$input_errors[] = gettext("A valid hostname is specified, but the domain name part should be omitted");
			}
		}
	}

	if (($_POST['ipaddr'] && !is_ipaddrv4($_POST['ipaddr']))) {
		$input_errors[] = gettext("A valid IPv4 address must be specified.");
	}

	if (($_POST['mac'] && !is_macaddr($_POST['mac']))) {
		$input_errors[] = gettext("A valid MAC address must be specified.");
	}

	/* Redmine #13584 */
	if (is_array($pconfig['numberoptions']['item'] ?? null)) {
		foreach ($pconfig['numberoptions']['item'] as $numberoption) {
			$numberoption_value = base64_decode($numberoption['value']);
			if ($numberoption['type'] == 'text' && strstr($numberoption_value, '"')) {
				$input_errors[] = gettext("Text type cannot include quotation marks.");
			}
		}
	}

	if (!$input_errors) {
		$mapent = array();
		$mapent['mac'] = $_POST['mac'];
		$mapent['cid'] = $_POST['cid'];
		$mapent['ipaddr'] = $_POST['ipaddr'];
		$mapent['hostname'] = $_POST['hostname'];
		$mapent['descr'] = $_POST['descr'];
		$mapent['filename'] = $_POST['filename'];
		$mapent['rootpath'] = $_POST['rootpath'];
		$mapent['filename32'] = $_POST['filename32'];
		$mapent['filename64'] = $_POST['filename64'];
		$mapent['filename32arm'] = $_POST['filename32arm'];
		$mapent['filename64arm'] = $_POST['filename64arm'];
		$mapent['uefihttpboot'] = $_POST['uefihttpboot'];
		$mapent['ldap'] = $_POST['ldap'];
		$mapent['numberoptions'] = $pconfig['numberoptions'] ?? array();

		if ($this_map_config) {
			config_set_path("dhcpd/{$if}/staticmap/{$id}", $mapent);
		} else {
			config_set_path("dhcpd/{$if}/staticmap/", $mapent);
		}
		staticmaps_sort($if);

		write_config("DHCP Server settings saved");

		if (config_path_enabled("dhcpd/{$if}")) {
			mark_subsystem_dirty('dhcpd');
		}
	}

	return $input_errors;
}
