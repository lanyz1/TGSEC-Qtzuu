<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function getMPDCRONSettings($pppif) {
	global $g;

	$cron_cmd_file = "{$g['varetc_path']}/pppoe_restart_{$pppif}";
	foreach (config_get_path('cron/item', []) as $i => $item) {
		if (stripos($item['command'], $cron_cmd_file) !== false) {
			return array("ID" => $i, "ITEM" => $item);
		}
	}

	return NULL;
}

function handle_pppoe_reset($post_array) {
	global $g;

	$pppif = "{$post_array['type']}{$post_array['ptpid']}";
	$cron_cmd_file = "{$g['varetc_path']}/pppoe_restart_{$pppif}";

	if (!is_array(config_get_path('cron/item'))) {
		if (config_set_path('cron/item', array()) === null)
			logger(LOG_DEBUG, localize_text('Cron section in config root is invalid.'));
			return;
	}

	$itemhash = getMPDCRONSettings($pppif);

	// reset cron items if necessary and return
	if (empty($post_array['pppoe-reset-type'])) {
		if (isset($itemhash)) {
			config_del_path("cron/item/{$itemhash['ID']}");
		}
		sigkillbypid("{$g['varrun_path']}/cron.pid", "HUP");
		return;
	}

	if (empty($itemhash)) {
		$itemhash = array();
	}
	$item = array();
	if (isset($post_array['pppoe-reset-type']) && $post_array['pppoe-reset-type'] == "custom") {
		$item['minute'] = (strlen($post_array['pppoe_resetminute']) > 0) ? $post_array['pppoe_resetminute'] : "*";
		$item['hour'] = (strlen($post_array['pppoe_resethour']) > 0) ? $post_array['pppoe_resethour'] : "*";
		if (isset($post_array['pppoe_resetdate']) && $post_array['pppoe_resetdate'] <> "") {
			$date = explode("/", $post_array['pppoe_resetdate']);
			$item['mday'] = $date[1];
			$item['month'] = $date[0];
		} else {
			$item['mday'] = "*";
			$item['month'] = "*";
		}
		$item['wday'] = "*";
		$item['who'] = "root";
		$item['command'] = $cron_cmd_file;
	} elseif (isset($post_array['pppoe-reset-type']) && $post_array['pppoe-reset-type'] == "preset") {
		switch ($post_array['pppoe_pr_preset_val']) {
			case "monthly":
				$item['minute'] = "0";
				$item['hour'] = "0";
				$item['mday'] = "1";
				$item['month'] = "*";
				$item['wday'] = "*";
				break;
			case "weekly":
				$item['minute'] = "0";
				$item['hour'] = "0";
				$item['mday'] = "*";
				$item['month'] = "*";
				$item['wday'] = "0";
				break;
			case "daily":
				$item['minute'] = "0";
				$item['hour'] = "0";
				$item['mday'] = "*";
				$item['month'] = "*";
				$item['wday'] = "*";
				break;
			case "hourly":
				$item['minute'] = "0";
				$item['hour'] = "*";
				$item['mday'] = "*";
				$item['month'] = "*";
				$item['wday'] = "*";
				break;
		} // end switch
		$item['who'] = "root";
		$item['command'] = $cron_cmd_file;
	}
	if (empty($item)) {
		return;
	}
	if (isset($itemhash['ID'])) {
		config_set_path("cron/item/{$itemhash['ID']}", $item);
	} else {
		config_set_path('cron/item/', $item);
	}
}
