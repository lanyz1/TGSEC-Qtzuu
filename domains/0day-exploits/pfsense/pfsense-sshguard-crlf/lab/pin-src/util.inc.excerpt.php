<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9
 * src/etc/inc/util.inc is_numericint and unlink_if_exists.
 * Do not edit by hand.
 */

/* validate non-negative numeric string, or equivalent numeric variable */
function is_numericint($arg) {
	$GLOBALS['lab_numericint_calls'][] = $arg;
	return (((is_int($arg) && $arg >= 0) || (is_string($arg) && strlen($arg) > 0 && ctype_digit(strval($arg)))) ? true : false);
}

function unlink_if_exists($fn) {
	$to_do = glob($fn);
	if (is_array($to_do) && count($to_do) > 0) {
		$results = @array_map("unlink", $to_do);
		$result = !in_array(false, $results, true);
	} else {
		$result = @unlink($fn);
	}
	return $result;
}
