<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function unlink_if_exists($fn) {
	$to_do = glob($fn);
	if (is_array($to_do) && count($to_do) > 0) {
		// Returns an array of boolean indicating if each unlink worked
		$results = @array_map("unlink", $to_do);
		// If there is no false in the array, then all went well
		$result = !in_array(false, $results, true);
	} else {
		$result = @unlink($fn);
	}
	return $result;
}
