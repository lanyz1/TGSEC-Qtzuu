<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9
 * src/usr/local/pfSense/include/www/system_advanced_admin.inc
 * doAdvancedAdminPOST whitelist is_subnet (closed) plus sshguard knob store.
 * sshguard_threshold / blocktime / detection_time are not is_numericint.
 * Do not edit by hand.
 */

function save_sshguard_from_post($post, $json = false) {
	$input_errors = array();
	$pconfig = $post;

	if ($json) {
		$pconfig['sshguard_whitelist'] = $post['sshguard_whitelist'];
	} else {
		$whitelist_addresses = array();
		for ($i = 0; isset($post['address' . $i]); $i++) {
			/* Ignore blank fields */
			if (empty($post['address' . $i])) {
				continue;
			}

			$whitelist_address = $post['address' . $i] . '/' .
			    $post['address_subnet'. $i];

			if (!is_subnet($whitelist_address)) {
				$input_errors[] = sprintf(gettext(
				    "Invalid subnet '%s' added to Login Protection pass list"),
				    $whitelist_address);
				break;
			}
			$whitelist_addresses[] = $whitelist_address;
		}


		$pconfig['sshguard_whitelist'] = implode(' ', $whitelist_addresses);
	}

	$restart_sshguard = false;
	if (!$input_errors) {
		if (config_get_path('system/sshguard_threshold') != $pconfig['sshguard_threshold']) {
			config_set_path('system/sshguard_threshold', $pconfig['sshguard_threshold']);
			$restart_sshguard = true;
		}
		if (config_get_path('system/sshguard_blocktime') != $pconfig['sshguard_blocktime']) {
			config_set_path('system/sshguard_blocktime', $pconfig['sshguard_blocktime']);
			$restart_sshguard = true;
		}
		if (config_get_path('system/sshguard_detection_time') != $pconfig['sshguard_detection_time']) {
			config_set_path('system/sshguard_detection_time', $pconfig['sshguard_detection_time']);
			$restart_sshguard = true;
		}
		if (config_get_path('system/sshguard_whitelist') != $pconfig['sshguard_whitelist']) {
			config_set_path('system/sshguard_whitelist', $pconfig['sshguard_whitelist']);
			$restart_sshguard = true;
		}

		write_config("Admin Access Advanced Settings saved");

		if ($restart_sshguard) {
			system_sshguard_stop();
			system_sshguard_start();
		}
	}

	return array(
		'input_errors' => $input_errors,
		'pconfig' => $pconfig,
		'restart_sshguard' => $restart_sshguard,
	);
}
