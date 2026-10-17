<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function is_numericint($arg) {
	return (((is_int($arg) && $arg >= 0) || (is_string($arg) && strlen($arg) > 0 && ctype_digit(strval($arg)))) ? true : false);
}
