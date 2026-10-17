<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function dyndns_edit_check_host($type, $host, $updateurl = 'http://127.0.0.1/update') {
	global $dyndns_split_domain_types, $ddns_attr;

	$pconfig = array('type' => $type);
	$_POST = array(
		'type' => $type,
		'host' => $host,
		'updateurl' => $updateurl,
		'username' => 'lab',
		'passwordfld' => 'lab',
		'passwordfld_confirm' => 'lab',
	);
	$input_errors = array();
	$reqdfields = array();
	$reqdfieldsn = array();
	$reqdfields = array("type");
	$reqdfieldsn = array(gettext("Service type"));

	if ($pconfig['type'] != "custom" && $pconfig['type'] != "custom-v6") {
		if ($pconfig['type'] != "dnsomatic") {
			$reqdfields[] = "host";
			$reqdfieldsn[] = gettext("Hostname");
		}
		$reqdfields[] = "passwordfld";
		$reqdfieldsn[] = gettext("Password");
		$reqdfields[] = "username";
		$reqdfieldsn[] = gettext("Username");
		if (in_array($pconfig['type'], $dyndns_split_domain_types)) {
			$reqdfields[] = "domainname";
			$reqdfieldsn[] = gettext("Domain name");
		}
	} else {
		$reqdfields[] = "updateurl";
		$reqdfieldsn[] = gettext("Update URL");
	}

	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

	if ($_POST['passwordfld'] != $_POST['passwordfld_confirm']) {
		$input_errors[] = gettext("Password and confirmed password must match.");
	}

	if (isset($_POST['check_ip_mode']) && !in_array($_POST['check_ip_mode'], array_keys(build_check_ip_mode_list()))) {
		$input_errors[] = gettext("The specified option for Check IP Mode is invalid.");
	}

	if (isset($_POST['host']) && in_array("host", $reqdfields)) {
		$allow_wildcard = false;
		if (((array_get_path($ddns_attr, "{$pconfig['type']}/apex") == true) && (($_POST['host'] == '@.') || ($_POST['host'] == '@'))) ||
		    ((array_get_path($ddns_attr, "{$pconfig['type']}/wildcard") == true) && (($_POST['host'] == '*.') || ($_POST['host'] == '*')))) {
			$host_to_check = $_POST['domainname'];
		} else {
			switch ($pconfig['type']) {
				case 'azure':
				case 'azurev6':
				case 'cloudflare':
				case 'cloudflare-v6':
				case 'gandi-livedns':
				case 'gandi-livedns-v6':
				case 'hover':
				case 'linode':
				case 'linode-v6':
				case 'name.com':
				case 'name.com-v6':
				case 'noip':
				case 'porkbun':
				case 'porkbun-v6':
				case 'yandex':
				case 'yandex-v6':
					$host_to_check = ($_POST['host'] == '@') ? $_POST['domainname'] : "{$_POST['host']}.{$_POST['domainname']}";
					$allow_wildcard = true;
					break;
				case 'route53':
				case 'route53-v6':
					$host_to_check = $_POST['host'];
					$allow_wildcard = true;
					break;
				default:
					$host_to_check = $_POST['host'];
			}
		}

		if ($pconfig['type'] != "custom" && $pconfig['type'] != "custom-v6") {
			if (!is_domain($host_to_check, $allow_wildcard)) {
				$input_errors[] = gettext("The hostname contains invalid characters.");
			}
		}

		unset($host_to_check);
	}

	$host_errors = array();
	foreach ($input_errors as $err) {
		if (is_string($err) && str_contains($err, 'hostname contains invalid characters')) {
			$host_errors[] = $err;
		}
	}

	return array(
		'errors' => array_values($input_errors),
		'host_errors' => $host_errors,
		'reqdfields' => $reqdfields,
		'host_required' => in_array('host', $reqdfields, true),
		'is_domain' => is_domain($host, false),
		'type' => $type,
		'host' => $host,
	);
}
