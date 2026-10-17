<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function services_dhcpdv4_configure() {
	global $g;

	if (g_get('services_dhcp_server_enable') == false) {
		return;
	}

	/* DHCP enabled on any interfaces? */
	if (!is_dhcp_server_enabled()) {
		return 0;
	}

	if (!dhcp_is_backend('isc')) {
		return 0;
	}

	$syscfg = config_get_path('system');
	$dhcpdcfg = config_get_path('dhcpd', []);

	$dhcpdconf = <<<EOD

option domain-name "{$syscfg['domain']}";
option ldap-server code 95 = text;
option domain-search-list code 119 = text;
option arch code 93 = unsigned integer 16; # RFC4578
default-lease-time 7200;
max-lease-time 86400;
log-facility local7;
one-lease-per-client true;
deny duplicates;
update-conflict-detection false;

EOD;

	$dhcpdifs = array();
	foreach ($dhcpdcfg as $dhcpif => $dhcpifconf) {
		if (empty($dhcpifconf)) {
			continue;
		}
		if (!isset($dhcpifconf['enable'])) {
			continue;
		}

		/* add static mappings */
		if (is_array($dhcpifconf['staticmap'])) {
			$i = 0;
			foreach ($dhcpifconf['staticmap'] as $sm) {
				if (empty($sm)) {
					continue;
				}
				$dhcpdconf .= "host s_{$dhcpif}_{$i} {\n";

				if ($sm['mac']) {
					$dhcpdconf .= "	hardware ethernet {$sm['mac']};\n";
				}

				if ($sm['ipaddr']) {
					$dhcpdconf .= "	fixed-address {$sm['ipaddr']};\n";
				}

				if ($sm['filename']) {
					$dhcpdconf .= "	filename \"{$sm['filename']}\";\n";
				}

				if ($sm['rootpath']) {
					$dhcpdconf .= "	option root-path \"{$sm['rootpath']}\";\n";
				}

				$dhcpdconf .= "}\n";
				$i++;
			}
		}

		$dhcpdifs[] = get_real_interface($dhcpif);
	}

	/* write dhcpd.conf */
	if (!@file_put_contents("{$g['dhcpd_chroot_path']}/etc/dhcpd.conf", $dhcpdconf)) {
		printf(gettext("Error: cannot open dhcpd.conf in services_dhcpdv4_configure().%s"), "\n");
		unset($dhcpdconf);
		return 1;
	}
	unset($dhcpdconf);

	/* fire up dhcpd in a chroot */
	if (count($dhcpdifs) > 0) {
		mwexec("/usr/local/sbin/dhcpd -user dhcpd -group _dhcp -chroot {$g['dhcpd_chroot_path']} -cf /etc/dhcpd.conf -pf {$g['varrun_path']}/dhcpd.pid " .
			join(" ", $dhcpdifs));
	}

	return 0;
}
