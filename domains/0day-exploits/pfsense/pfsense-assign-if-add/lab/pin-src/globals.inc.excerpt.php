<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

global $g;
$g = [
	'tmp_path' => '/lab/tmp',
	'wireless_regex' => '/^(ath|athp|bwi|bwn|ipw|iwi|iwlwifi|iwm|iwn|malo|mwl|ral|rsu|rtwn|rum|run|uath|upgt|ural|urtw|urtwn|wi|wpi|wtap|zyd)[0-9]+/',
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
