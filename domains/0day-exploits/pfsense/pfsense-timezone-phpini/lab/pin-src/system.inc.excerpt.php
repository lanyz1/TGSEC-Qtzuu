<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function system_get_timezone_list() {
	global $g;

	$file_list = array_merge(
		glob("/usr/share/zoneinfo/[A-Z]*"),
		glob("/usr/share/zoneinfo/*/*"),
		glob("/usr/share/zoneinfo/*/*/*")
	);

	if (empty($file_list)) {
		$file_list[] = g_get('default_timezone');
	} else {
		/* Remove directories from list */
		$file_list = array_filter($file_list, function($v) {
			return !is_dir($v);
		});
	}

	/* Remove directory prefix */
	$file_list = str_replace('/usr/share/zoneinfo/', '', $file_list);

	sort($file_list);

	return $file_list;
}

function system_timezone_configure() {
	global $g;
	if (g_get('debug')) {
		$mt = microtime();
		echo "system_timezone_configure() being called $mt\n";
	}

	$syscfg = config_get_path('system');

	if (is_platform_booting()) {
		echo gettext("Setting timezone...");
	}

	/* extract appropriate timezone file */
	$timezone = (isset($syscfg['timezone']) ? $syscfg['timezone'] : g_get('default_timezone'));
	/* DO NOT remove \n otherwise tzsetup will fail */
	@file_put_contents("/var/db/zoneinfo", $timezone . "\n");
	mwexec("/usr/sbin/tzsetup -r");

	if (is_platform_booting()) {
		echo gettext("done.") . "\n";
	}
}
