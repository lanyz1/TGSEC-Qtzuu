<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

$g = [
	'captiveportal_path' => '/usr/local/captiveportal',
	'captiveportal_element_path' => '/var/db/cpelements',
	'captiveportal_element_sizelimit' => 1048576,
];

function g_has(string $key, bool $isset = false) : bool
{
	global $g;
	return (array_key_exists($key, $g) && (!$isset || isset($g[$key])));
}

function g_get(string $key, mixed $default = null) : mixed
{
	global $g;
	return (g_has($key, true) ? $g[$key] : $default);
}
