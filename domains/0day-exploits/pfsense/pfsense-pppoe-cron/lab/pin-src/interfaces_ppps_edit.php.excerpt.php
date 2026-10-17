<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function ppps_edit_reset_validate() {
	$input_errors = array();
	if ($_POST['pppoe-reset-type'] == "custom" && $_POST['pppoe_resethour'] <> "" && !is_numericint($_POST['pppoe_resethour']) &&
	    $_POST['pppoe_resethour'] >= 0 && $_POST['pppoe_resethour'] <=23) {
		$input_errors[] = gettext("A valid PPPoE reset hour must be specified (0-23).");
	}
	if ($_POST['pppoe-reset-type'] == "custom" && $_POST['pppoe_resetminute'] <> "" && !is_numericint($_POST['pppoe_resetminute']) &&
	    $_POST['pppoe_resetminute'] >= 0 && $_POST['pppoe_resetminute'] <=59) {
		$input_errors[] = gettext("A valid PPPoE reset minute must be specified (0-59).");
	}
	return $input_errors;
}
