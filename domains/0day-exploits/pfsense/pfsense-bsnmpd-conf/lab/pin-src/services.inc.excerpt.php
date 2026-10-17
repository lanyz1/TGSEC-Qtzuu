<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_snmpd_configure($interface='') {
	global $g;
	if (g_get('debug')) {
		$mt = microtime();
		echo "services_snmpd_configure() being called $mt\n";
	}

	$bindip = config_get_path('snmpd/bindip', "");
	if (!empty($interface) &&
	    !empty($bind_ip) &&
	    config_path_enabled('snmpd')) {
		foreach (explode(",", $bindip) as $bind_to_ip) {
			if ($bind_to_ip == $interface) {
				$interface_restart = true;
				break;
			}
		}
		if (!$interface_restart) {
			return 0;
		}
	}

	/* kill any running snmpd */
	sigkillbypid("{$g['varrun_path']}/snmpd.pid", "TERM");
	sleep(2);
	if (is_process_running("bsnmpd")) {
		mwexec("/usr/bin/killall bsnmpd", true);
	}

	if (config_path_enabled('snmpd')) {

		if (is_platform_booting()) {
			echo gettext("Starting SNMP daemon... ");
		}

		/* Make sure a printcap file exists or else bsnmpd will log errors. See https://redmine.pfsense.org/issues/6838 */
		if (!file_exists('/etc/printcap')) {
			@file_put_contents('/etc/printcap', "# Empty file to prevent bsnmpd from logging errors.\n");
		}

		/* generate snmpd.conf */
		$fd = fopen("{$g['varetc_path']}/snmpd.conf", "w");
		if (!$fd) {
			printf(gettext("Error: cannot open snmpd.conf in services_snmpd_configure().%s"), "\n");
			return 1;
		}

		$snmpdcfg = config_get_path('snmpd');
		$snmpdconf = <<<EOD
location := "{$snmpdcfg['syslocation']}"
contact := "{$snmpdcfg['syscontact']}"
read := "{$snmpdcfg['rocommunity']}"

EOD;

/* No docs on what write strings do there so disable for now.
		if (config_path_enabled('snmpd','rwenable') && preg_match('/^\S+$/', $snmpdcfg['rwcommunity'])) {
			$snmpdconf .= <<<EOD
# write string
write := "{$snmpdcfg['rwcommunity']}"

EOD;
		}
*/


		if (config_path_enabled('snmpd','trapenable') && preg_match('/^\S+$/', $snmpdcfg['trapserver'])) {
			$snmpdconf .= <<<EOD
# SNMP Trap support.
traphost := {$snmpdcfg['trapserver']}
trapport := {$snmpdcfg['trapserverport']}
trap := "{$snmpdcfg['trapstring']}"


EOD;
		}

		$sysDescr = "{$g['product_label']} " .
				  config_get_path('system/hostname') . '.' .config_get_path('system/domain') .
			" {$g['product_version_string']} " . php_uname("s") .
			" " . php_uname("r") . " " . php_uname("m");

		$snmpdconf .= <<<EOD
system := 1     # pfSense
%snmpd
sysDescr			= "{$sysDescr}"
begemotSnmpdDebugDumpPdus       = 2
begemotSnmpdDebugSyslogPri      = 7
begemotSnmpdCommunityString.0.1 = $(read)

EOD;

/* No docs on what write strings do there so disable for now.
		if (isset($config['snmpd']['rwcommunity']) && preg_match('/^\S+$/', $config['snmpd']['rwcommunity'])) {
			$snmpdconf .= <<<EOD
begemotSnmpdCommunityString.0.2 = $(write)

EOD;
		}
*/


		if (config_path_enabled('snmpd','trapenable') && preg_match('/^\S+$/', config_get_path('snmpd/trapserver'))) {
			$snmpdconf .= <<<EOD
begemotTrapSinkStatus.[$(traphost)].$(trapport) = 4
begemotTrapSinkVersion.[$(traphost)].$(trapport) = 2
begemotTrapSinkComm.[$(traphost)].$(trapport) = $(trap)

EOD;
		}


		$snmpdconf .= <<<EOD
begemotSnmpdCommunityDisable    = 1

EOD;

		$bind_to_ips = array();
		$bind_to_ip6s = array();
		if (config_path_enabled('snmpd','bindip')) {
			$ipproto = config_get_path('snmpd/ipprotocol', "4");
			if (strstr($ipproto, "4")) {
				$inet4 = true;
			}
			if (strstr($ipproto, "6")) {
				$inet6 = true;
			}
			foreach (array_filter(explode(",", config_get_path('snmpd/bindip', ""))) as $bind_to_ip) {
				if (is_ipaddr($bind_to_ip)) {
					$bind_to_ips[] = $bind_to_ip;
				} else {
					$if = get_real_interface($bind_to_ip);
					if (does_interface_exist($if)) {
						if ($inet4) {
							$bindip = get_interface_ip($bind_to_ip);
							if (is_ipaddrv4($bindip)) {
								$bind_to_ips[] = $bindip;
							}
						}
						if ($inet6) {
							$bindip6 = get_interface_ipv6($bind_to_ip);
							if (is_ipaddrv6($bindip6)) {
								$bind_to_ip6s[] = $bindip6;
							}
						}
					}
				}
			}
		}
		if (!count($bind_to_ips) && $inet4) {
			$bind_to_ips = array("0.0.0.0");
		}
		if (!count($bind_to_ip6s) && $inet6) {
			$bind_to_ip6s = array("::");
		}

		$pollport = config_get_path('snmpd/pollport');
		if (is_port($pollport)) {
			foreach ($bind_to_ips as $bind_to_ip) {
				$snmpdconf .= <<<EOD
begemotSnmpdTransInetStatus.1.4.{$bind_to_ip}.{$pollport}.1 = 4

EOD;

			}
			foreach ($bind_to_ip6s as $bind_to_ip6) {
				$bind_to_ip6 = ip6_to_asn1($bind_to_ip6);
				$snmpdconf .= <<<EOD
begemotSnmpdTransInetStatus.2.16.{$bind_to_ip6}{$pollport}.1 = 4

EOD;

			}
		}

		$snmpdconf .= <<<EOD
begemotSnmpdLocalPortStatus."/var/run/snmpd.sock" = 1
begemotSnmpdLocalPortType."/var/run/snmpd.sock" = 4

# These are bsnmp macros not php vars.
sysContact      = $(contact)
sysLocation     = $(location)
sysObjectId     = 1.3.6.1.4.1.12325.1.1.2.1.$(system)

snmpEnableAuthenTraps = 2

EOD;

		if (config_path_enabled('snmpd/modules', 'mibii')) {
			$snmpdconf .= <<<EOD
begemotSnmpdModulePath."mibII"  = "/usr/lib/snmp_mibII.so"

EOD;
		}

		if (config_path_enabled('snmpd/modules', 'netgraph')) {
			$snmpdconf .= <<<EOD
begemotSnmpdModulePath."netgraph" = "/usr/lib/snmp_netgraph.so"
%netgraph
begemotNgControlNodeName = "snmpd"

EOD;
		}

		if (config_path_enabled('snmpd/modules', 'pf')) {
			$snmpdconf .= <<<EOD
begemotSnmpdModulePath."pf"     = "/usr/lib/snmp_pf.so"

EOD;
		}

		if (config_path_enabled('snmpd/modules', 'hostres')) {
			$snmpdconf .= <<<EOD
begemotSnmpdModulePath."hostres"     = "/usr/lib/snmp_hostres.so"

EOD;
		}

		if (config_path_enabled('snmpd/modules', 'bridge')) {
			$snmpdconf .= <<<EOD
begemotSnmpdModulePath."bridge"     = "/usr/lib/snmp_bridge.so"
# config must end with blank line

EOD;
		}
		if (config_path_enabled('snmpd/modules', 'ucd')) {
			$snmpdconf .= <<<EOD
begemotSnmpdModulePath."ucd"     = "/usr/local/lib/snmp_ucd.so"

EOD;
		}
		if (config_path_enabled('snmpd/modules', 'regex')) {
				$snmpdconf .= <<<EOD
begemotSnmpdModulePath."regex"     = "/usr/local/lib/snmp_regex.so"

EOD;
		}

		fwrite($fd, $snmpdconf);
		fclose($fd);
		unset($snmpdconf);

		/* run bsnmpd */
		mwexec("/usr/sbin/bsnmpd -c {$g['varetc_path']}/snmpd.conf" .
			" -p {$g['varrun_path']}/snmpd.pid");

		if (is_platform_booting()) {
			echo gettext("done.") . "\n";
		}
	}

	return 0;
}
