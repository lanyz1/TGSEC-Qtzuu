<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */
/* src/usr/local/pfSense/include/www/firewall_nat.inc reorderNATrules */

// Re-order the NAT rules per the array of indices passed in $post
function reorderNATrules($post, $json = false) {
	$updated = false;
	$dirty = false;

	$a_separators = config_get_path('nat/separator', []);

	/* update rule order, POST[rule] is an array of ordered IDs */
	if (is_array($post['rule']) && !empty($post['rule'])) {
		if (set_anynat_rules_order('rdr', $post['rule'])) {
			$dirty = true;
		}
	}

	/* update separator order, POST[separator] is an array of ordered IDs */
	if (is_array($post['separator']) && !empty($post['separator'])) {
		$new_separator = array();
		$idx = 0;

		foreach ($post['separator'] as $separator) {
			$new_separator['sep' . $idx++] = $separator;
		}

		if ($a_separators !== $new_separator) {
			$a_separators = $new_separator;
			$updated = true;
		}
	} else if (!empty($a_separators)) {
		$a_separators = "";
		$updated = true;
	}

	if ($updated || $dirty) {
		config_set_path('nat/separator', $a_separators);
		if (write_config("NAT: Rule order changed")) {
			if ($json) {
				filter_configure();
			} else if ($dirty) {
				mark_subsystem_dirty('natconf');
			}
		}
	}

	if(!$json) {
		header("Location: firewall_nat.php");
		exit;
	}
}
