<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9
 * src/etc/inc/syslog.inc system_sshguard_start / system_sshguard_stop.
 * Do not edit by hand.
 */

function system_sshguard_start() {
	$sshguard_whitelist = array();
	if (!empty(config_get_path('system/sshguard_whitelist'))) {
		$sshguard_whitelist = explode(' ',
		    config_get_path('system/sshguard_whitelist'));
	}

	$sshguard_config = array();
	$sshguard_config[] = 'FILES="' . g_get('varlog_path') . '/auth.log"' . "\n";
	$sshguard_config[] = 'BACKEND="/usr/local/libexec/sshg-fw-pf"' . "\n";
	if (!empty(config_get_path('system/sshguard_threshold'))) {
		$sshguard_config[] = 'THRESHOLD=' .
		    config_get_path('system/sshguard_threshold') . "\n";
	}
	if (!empty(config_get_path('system/sshguard_blocktime'))) {
		$sshguard_config[] = 'BLOCK_TIME=' .
		    config_get_path('system/sshguard_blocktime') . "\n";
	}
	if (!empty(config_get_path('system/sshguard_detection_time'))) {
		$sshguard_config[] = 'DETECTION_TIME=' .
		    config_get_path('system/sshguard_detection_time') . "\n";
	}
	if (!empty($sshguard_whitelist)) {
		@file_put_contents("/usr/local/etc/sshguard.whitelist",
		    implode(PHP_EOL, $sshguard_whitelist));
		$sshguard_config[] =
		    'WHITELIST_FILE=/usr/local/etc/sshguard.whitelist' . "\n";
	} else {
		unlink_if_exists("/usr/local/etc/sshguard.whitelist");
	}
	file_put_contents("/usr/local/etc/sshguard.conf", $sshguard_config);

	mwexec_bg('/usr/sbin/daemon -R 60 -P /var/run/daemon_sshguard.pid -t sshguard /usr/local/sbin/sshguard -i /var/run/sshguard.pid');
}

function system_sshguard_stop() {
	mwexec_bg('pkill -f "' . str_replace('/', '\\/', g_get('varlog_path')) . '\\/auth\.log|[[:<:]](sshguard|sshg-parser|sshg-fw-pf|sshg-blocker)[[:>:]]"');
}
