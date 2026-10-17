<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

##|+PRIV
##|*IDENT=page-system-generalsetup
##|*NAME=System: General Setup
##|*DESCR=Allow access to the 'System: General Setup' page.
##|*MATCH=system.php*
##|-PRIV

function is_timezone($elt) {
	return !preg_match("/\/$/", $elt);
}

function system_general_save() {
		$system_config = config_get_path('system');
		update_if_changed("hostname", $system_config['hostname'], $_POST['hostname']);
		update_if_changed("domain", $system_config['domain'], $_POST['domain']);
		update_if_changed("timezone", $system_config['timezone'], $_POST['timezone']);
		update_if_changed("NTP servers", $system_config['timeservers'], strtolower($_POST['timeservers']));
		config_set_path('system', $system_config);
}
