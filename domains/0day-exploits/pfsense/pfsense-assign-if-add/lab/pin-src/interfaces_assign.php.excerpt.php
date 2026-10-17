<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function assign_add_if_add() {
	global $action_msg, $class;

	if (isset($_REQUEST['add']) && isset($_REQUEST['if_add'])) {
		/* Be sure this port is not being used */
		$portused = false;
		foreach (config_get_path('interfaces', []) as $ifdata) {
			if ($ifdata['if'] == $_REQUEST['if_add']) {
				$portused = true;
				break;
			}
		}

		if ($portused === false) {
			/* find next free optional interface number */
			if (!config_get_path('interfaces/lan')) {
				$newifname = "lan";
				$descr = "LAN";
			} else {
				$interface_count = count(config_get_path('interfaces', []));
				for ($i = 1; $i <= $interface_count; $i++) {
					if (!config_get_path("interfaces/opt{$i}")) {
						break;
					}
				}
				$newifname = 'opt' . $i;
				$descr = "OPT" . $i;
			}

			config_set_path("interfaces/{$newifname}", [
				'descr' => $descr,
				'if' => $_POST['if_add']
			]);
			if (preg_match(g_get('wireless_regex'), $_POST['if_add'])) {
				config_set_path("interfaces/{$newifname}/wireless", []);
				$new_if_config = config_get_path("interfaces/{$newifname}");
				interface_sync_wireless_clones($new_if_config, false);
				config_set_path("interfaces/{$newifname}", $new_if_config);
			}


			$if_config = config_get_path('interfaces', []);
			uksort($if_config, "compare_interface_friendly_names");
			config_set_path('interfaces', $if_config);

			write_config("New interface assigned");

			filter_configure();

			$action_msg = gettext("Interface has been added.");
			$class = "success";
			return $newifname;
		}
	}
	return null;
}

function assign_submit_remap() {
	global $portlist, $input_errors;

	if (isset($_POST['Submit'])) {

		$input_errors = array();

		/* input validation */

		/* Build a list of the port names so we can see how the interfaces map */
		$portifmap = array();
		foreach ($portlist as $portname => $portinfo) {
			$portifmap[$portname] = array();
		}

		/* Go through the list of ports selected by the user,
		build a list of port-to-interface mappings in portifmap */
		foreach ($_POST as $ifname => $ifport) {
			if (($ifname == 'lan') || ($ifname == 'wan') || (substr($ifname, 0, 3) == 'opt')) {
				if (array_key_exists($ifport, $portlist)) {
					$portifmap[$ifport][] = strtoupper($ifname);
				} else {
					$input_errors[] = sprintf(gettext('Cannot set port %1$s because the submitted interface does not exist.'), $ifname);
				}
			}
		}

		if (!$input_errors) {
			/* No errors detected, so update the config */
			foreach ($_POST as $ifname => $ifport) {

				if (($ifname == 'lan') || ($ifname == 'wan') || (substr($ifname, 0, 3) == 'opt')) {

					if (!is_array($ifport)) {
						$this_if_config = config_get_path("interfaces/{$ifname}");
						$this_if_config['if'] = $ifport;
						/* check for wireless interfaces, set or clear ['wireless'] */
						if (preg_match(g_get('wireless_regex'), $ifport)) {
							if (!is_array($this_if_config['wireless'])) {
								$this_if_config['wireless'] = array();
							}
						} else {
							unset($this_if_config['wireless']);
						}
						config_set_path("interfaces/{$ifname}", $this_if_config);
					}
				}
			}
			write_config("Interfaces assignment settings changed");
		}
	}
}
