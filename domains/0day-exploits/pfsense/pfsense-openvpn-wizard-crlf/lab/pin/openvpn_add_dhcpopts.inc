<?php
/* Copied verbatim from pfsense src/etc/inc/openvpn.inc:695-762
 * pin 9363ac5b8651a1c7a333180425ce7719070f95f9 */

function openvpn_add_dhcpopts(& $settings, & $conf) {

	if (!empty($settings['dns_domain'])) {
		$conf .= "push \"dhcp-option DOMAIN {$settings['dns_domain']}\"\n";
	}

	if (!empty($settings['dns_server1'])) {
		$dnstype = (is_ipaddrv6($settings['dns_server1'])) ? "DNS6" : "DNS";
		$conf .= "push \"dhcp-option {$dnstype} {$settings['dns_server1']}\"\n";
	}
	if (!empty($settings['dns_server2'])) {
		$dnstype = (is_ipaddrv6($settings['dns_server2'])) ? "DNS6" : "DNS";
		$conf .= "push \"dhcp-option {$dnstype} {$settings['dns_server2']}\"\n";
	}
	if (!empty($settings['dns_server3'])) {
		$dnstype = (is_ipaddrv6($settings['dns_server3'])) ? "DNS6" : "DNS";
		$conf .= "push \"dhcp-option {$dnstype} {$settings['dns_server3']}\"\n";
	}
	if (!empty($settings['dns_server4'])) {
		$dnstype = (is_ipaddrv6($settings['dns_server4'])) ? "DNS6" : "DNS";
		$conf .= "push \"dhcp-option {$dnstype} {$settings['dns_server4']}\"\n";
	}

	if (!empty($settings['push_blockoutsidedns'])) {
		$conf .= "push \"block-outside-dns\"\n";
	}
	if (!empty($settings['push_register_dns'])) {
		$conf .= "push \"register-dns\"\n";
	}

	if (!empty($settings['ntp_server1'])) {
		$conf .= "push \"dhcp-option NTP {$settings['ntp_server1']}\"\n";
	}
	if (!empty($settings['ntp_server2'])) {
		$conf .= "push \"dhcp-option NTP {$settings['ntp_server2']}\"\n";
	}

	if ($settings['netbios_enable']) {

		if (!empty($settings['netbios_ntype']) && ($settings['netbios_ntype'] != 0)) {
			$conf .= "push \"dhcp-option NBT {$settings['netbios_ntype']}\"\n";
		}
		if (!empty($settings['netbios_scope'])) {
			$conf .= "push \"dhcp-option NBS {$settings['netbios_scope']}\"\n";
		}

		if (!empty($settings['wins_server1'])) {
			$conf .= "push \"dhcp-option WINS {$settings['wins_server1']}\"\n";
		}
		if (!empty($settings['wins_server2'])) {
			$conf .= "push \"dhcp-option WINS {$settings['wins_server2']}\"\n";
		}

		if (!empty($settings['nbdd_server1'])) {
			$conf .= "push \"dhcp-option NBDD {$settings['nbdd_server1']}\"\n";
		}
		if (!empty($settings['nbdd_server2'])) {
			$conf .= "push \"dhcp-option NBDD {$settings['nbdd_server2']}\"\n";
		}
	}

	if ($settings['gwredir']) {
		$conf .= "push \"redirect-gateway def1\"\n";
	}
	if ($settings['gwredir6']) {
		$conf .= "push \"redirect-gateway ipv6\"\n";
	}
}
