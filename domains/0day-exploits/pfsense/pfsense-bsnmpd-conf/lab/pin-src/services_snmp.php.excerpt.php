<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_snmp_save_from_post() {
	global $input_errors, $pconfig, $changes_applied, $retval;

	unset($input_errors);
	$pconfig = $_POST;

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

	/* input validation */
	if ($_POST['enable']) {
		if (strstr($_POST['syslocation'], "#")) {
			$input_errors[] = gettext("Invalid character '#' in system location");
		}
		if (strstr($_POST['syscontact'], "#")) {
			$input_errors[] = gettext("Invalid character '#' in system contact");
		}
		if (strstr($_POST['rocommunity'], "#")) {
			$input_errors[] = gettext("Invalid character '#' in read community string");
		}

		$reqdfields = explode(" ", "rocommunity");
		$reqdfieldsn = array(gettext("Community"));
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

		$reqdfields = explode(" ", "pollport");
		$reqdfieldsn = array(gettext("Polling Port"));
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);


	}

	if ($_POST['trapenable']) {
		if (strstr($_POST['trapstring'], "#")) {
			$input_errors[] = gettext("Invalid character '#' in SNMP trap string");
		}

		$reqdfields = explode(" ", "trapserver");
		$reqdfieldsn = array(gettext("Trap server"));
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

		$reqdfields = explode(" ", "trapserverport");
		$reqdfieldsn = array(gettext("Trap server port"));
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

		$reqdfields = explode(" ", "trapstring");
		$reqdfieldsn = array(gettext("Trap string"));
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	}

/* disabled until some docs show up on what this does.
	if ($_POST['rwenable']) {
		$reqdfields = explode(" ", "rwcommunity");
		$reqdfieldsn = explode(",", "Write community string");
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	}
*/



	if (!$input_errors) {
		config_set_path('snmpd/enable', $_POST['enable'] ? true : false);
		config_set_path('snmpd/pollport', $_POST['pollport']);
		config_set_path('snmpd/syslocation', $_POST['syslocation']);
		config_set_path('snmpd/syscontact', $_POST['syscontact']);
		config_set_path('snmpd/rocommunity', $_POST['rocommunity']);
		/* disabled until some docs show up on what this does.
		$config['snmpd']['rwenable'] = $_POST['rwenable'] ? true : false;
		$config['snmpd']['rwcommunity'] = $_POST['rwcommunity'];
		*/
		config_set_path('snmpd/trapenable', $_POST['trapenable'] ? true : false);
		config_set_path('snmpd/trapserver', $_POST['trapserver']);
		config_set_path('snmpd/trapserverport', $_POST['trapserverport']);
		config_set_path('snmpd/trapstring', $_POST['trapstring']);

		config_set_path('snmpd/modules/mibii', $_POST['mibii'] ? true : false);
		config_set_path('snmpd/modules/netgraph', $_POST['netgraph'] ? true : false);
		config_set_path('snmpd/modules/pf', $_POST['pf'] ? true : false);
		config_set_path('snmpd/modules/hostres', $_POST['hostres'] ? true : false);
		config_set_path('snmpd/modules/bridge', $_POST['bridge'] ? true : false);
		config_set_path('snmpd/modules/ucd', $_POST['ucd'] ? true : false);
		config_set_path('snmpd/modules/regex', $_POST['regex'] ? true : false);

		config_set_path('snmpd/ipprotocol', $_POST['ipprotocol']);
		if (is_array($_POST['bindip']) && !empty($_POST['bindip'])) {
			config_set_path('snmpd/bindip', implode(",", $_POST['bindip']));
		}

		write_config("SNMP settings saved");

		$changes_applied = true;
		$retval = 0;
		$retval |= services_snmpd_configure();
	}
}

	return $input_errors;
}
