<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_ntpd_pps_save_from_post() {
	global $input_errors, $serialports, $changes_applied, $retval;

	$serialports = get_serial_ports(true);
	unset($input_errors);
	$input_errors = array();

if ($_POST) {
	unset($input_errors);
	$input_errors = array();

	if (!empty($_POST['ppsport']) && !array_key_exists($_POST['ppsport'], $serialports)) {
		$input_errors[] = gettext("The selected PPS port does not exist.");
	}

	if (!$input_errors) {
		if (!empty($_POST['ppsport']) && array_key_exists($_POST['ppsport'], $serialports)) {
			config_set_path('ntpd/pps/port', $_POST['ppsport']);
		} else {
			config_del_path('ntpd/pps');
		}

		if (!empty($_POST['ppsfudge1'])) {
			config_set_path('ntpd/pps/fudge1', $_POST['ppsfudge1']);
		} else {
			config_del_path('ntpd/pps/fudge1');
		}

		if (!empty($_POST['ppsstratum']) && ($_POST['ppsstratum']) < 17) {
			config_set_path('ntpd/pps/stratum', $_POST['ppsstratum']);
		} else {
			config_del_path('ntpd/pps/stratum');
		}

		if (!empty($_POST['ppsrefid'])) {
			config_set_path('ntpd/pps/refid', $_POST['ppsrefid']);
		} else {
			config_del_path('ntpd/pps/refid');
		}

		write_config("Updated NTP PPS Settings");

		$changes_applied = true;
		$retval = 0;
		$retval |= system_ntp_configure();
	}
}

	return $input_errors;
}
