<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */
/* src/usr/local/www/firewall_rules.php order-store separator copy. Header redirect omitted. */

function firewall_rules_order_store($if) {
	$updated = false;
	$dirty = false;
	/* update rule order, POST[rule] is an array of ordered IDs */
	if (is_array($_POST['rule']) && !empty($_POST['rule'])) {
		$dirty = set_filter_rules_order($_POST['rule']);
	}

	$a_separators = config_get_path('filter/separator/' . strtolower($if), []);

	/* update separator order, POST[separator] is an array of ordered IDs */
	if (is_array($_POST['separator']) && !empty($_POST['separator'])) {
		$new_separator = array();
		$idx = 0;

		foreach ($_POST['separator'] as $separator) {
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
		config_set_path('filter/separator/' . strtolower($if), $a_separators);
		if (write_config(gettext("Firewall: Rules - reordered firewall rules."))) {
			if ($dirty) {
				mark_subsystem_dirty('filter');
			}
		}
	}

	return $a_separators;
}
