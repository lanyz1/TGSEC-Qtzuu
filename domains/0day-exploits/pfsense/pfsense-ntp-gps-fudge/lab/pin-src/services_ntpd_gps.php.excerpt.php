<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_ntpd_gps_save_from_post() {
	global $input_errors, $serialports, $changes_applied, $retval;

	$serialports = get_serial_ports(true);
	unset($input_errors);
	$input_errors = array();

if ($_POST) {
	$input_errors = array();
	if (!empty($_POST['gpsport']) && !array_key_exists($_POST['gpsport'], $serialports)) {
		$input_errors[] = gettext("The selected GPS port does not exist.");
	}

if ($_POST && empty($input_errors)) {

	if (!empty($_POST['gpsport']) && array_key_exists($_POST['gpsport'], $serialports)) {
		config_set_path('ntpd/gps/port', $_POST['gpsport']);
	} else {
		config_del_path('ntpd/gps');
	}

	if (!empty($_POST['gpsfudge1'])) {
		config_set_path('ntpd/gps/fudge1', $_POST['gpsfudge1']);
	} else {
		config_del_path('ntpd/gps/fudge1');
	}

	if (!empty($_POST['gpsfudge2'])) {
		config_set_path('ntpd/gps/fudge2', $_POST['gpsfudge2']);
	} else {
		config_del_path('ntpd/gps/fudge2');
	}

	if (!empty($_POST['gpsstratum']) && ($_POST['gpsstratum']) < 17) {
		config_set_path('ntpd/gps/stratum', $_POST['gpsstratum']);
	} else {
		config_del_path('ntpd/gps/stratum');
	}

	if (!empty($_POST['gpsrefid'])) {
		config_set_path('ntpd/gps/refid', $_POST['gpsrefid']);
	} else {
		config_del_path('ntpd/gps/refid');
	}

	write_config(gettext("Updated NTP GPS Settings"));

	$changes_applied = true;
	$retval = 0;
	$retval |= system_ntp_configure();
}

}

	return $input_errors;
}
