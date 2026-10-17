<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function clone_inuse($num) {
	$a_clones = config_get_path('wireless/clone', []);
	$iflist = get_configured_interface_list(true);
	$if_config = config_get_path('interfaces', []);
	foreach ($iflist as $if) {
		if ($if_config[$if]['if'] == $a_clones[$num]['cloneif']) {
			return true;
		}
	}

	return false;
}

function clone_compare($a, $b) {
	return strnatcmp($a['cloneif'], $b['cloneif']);
}

function wireless_edit_save() {
	global $id, $this_clone_config, $input_errors, $clone, $wlan_modes;

	if ($_POST['save']) {
		unset($input_errors);
		$pconfig = $_POST;

		/* input validation */
		$reqdfields = explode(" ", "if mode");
		$reqdfieldsn = array(gettext("Parent interface"), gettext("Mode"));

		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);

		if (!$input_errors) {
			$clone = array();
			$clone['if'] = $_POST['if'];
			$clone['mode'] = $_POST['mode'];
			$clone['descr'] = $_POST['descr'];

			if ($this_clone_config) {
				if ($clone['if'] == $this_clone_config['if']) {
					$clone['cloneif'] = $this_clone_config['cloneif'];
				}
			}

			if (!$clone['cloneif']) {
				$clone_id = 0;
				do {
					$clone_exists = false;
					$clone['cloneif'] = "{$_POST['if']}_wlan{$clone_id}";
					foreach (config_get_path('wireless/clone', []) as $existing) {
						if ($clone['cloneif'] == $existing['cloneif']) {
							$clone_exists = true;
							$clone_id++;
							break;
						}
					}
				} while ($clone_exists);
			}

			if ($this_clone_config) {
				if (clone_inuse($id)) {
					if ($clone['if'] != $this_clone_config['if']) {
						$input_errors[] = gettext("This wireless clone cannot be modified because it is still assigned as an interface.");
					} else if ($clone['mode'] != $this_clone_config['mode']) {
						$input_errors[] = gettext("Use the configuration page for the assigned interface to change the mode.");
					}
				}
			}

			if (!$input_errors) {
				if (!interface_wireless_clone($clone['cloneif'], $clone)) {
					$input_errors[] = sprintf(gettext('Error creating interface with mode %1$s.	 The %2$s interface may not support creating more clones with the selected mode.'), $wlan_modes[$clone['mode']], $clone['if']);
				} else {
					if ($this_clone_config) {
						if ($clone['if'] != $this_clone_config['if']) {
							pfSense_interface_destroy($this_clone_config['cloneif']);
						}
						$input_errors[] = sprintf(gettext("Created with id %s"), $id);
						config_set_path("wireless/clone/{$id}", $clone);
					} else {
						$input_errors[] = gettext("Created without id");
						config_set_path('wireless/clone/', $clone);
					}

					$a_clones = config_get_path('wireless/clone', []);
					usort($a_clones, "clone_compare");
					config_set_path('wireless/clone', $a_clones);
					write_config("Wireless interface added");
				}
			}
		}
	}
}
