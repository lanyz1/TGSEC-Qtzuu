<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function do_input_validation($postdata, $reqdfields, $reqdfieldsn, &$input_errors) {

	/* check for bad control characters */
	foreach ($postdata as $pn => $pd) {
		if (is_string($pd) && preg_match("/[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]/", $pd)) {
			$input_errors[] = sprintf(gettext("The field %s contains invalid characters."), $pn);
		}
	}

	if (is_array($reqdfields)) {
		for ($i = 0; $i < count($reqdfields); $i++) {
			if ($postdata[$reqdfields[$i]] == "") {
				$input_errors[] = sprintf(gettext("The field %s is required."), $reqdfieldsn[$i]);
			}
		}
	}
}
