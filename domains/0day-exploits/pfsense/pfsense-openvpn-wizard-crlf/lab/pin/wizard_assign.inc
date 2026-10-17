<?php
/* Copied verbatim from pfsense src/usr/local/www/wizards/openvpn_wizard.inc:659-684
 * pin 9363ac5b8651a1c7a333180425ce7719070f95f9 */

function wizard_copy_step10($pconfig) {
	$server = array();
	if (isset($pconfig['step10']['defaultdomain']))
		$server['dns_domain'] = $pconfig['step10']['defaultdomain'];
	if (isset($pconfig['step10']['dns1']))
		$server['dns_server1'] = $pconfig['step10']['dns1'];
	if (isset($pconfig['step10']['dns2']))
		$server['dns_server2'] = $pconfig['step10']['dns2'];
	if (isset($pconfig['step10']['dns3']))
		$server['dns_server3'] = $pconfig['step10']['dns3'];
	if (isset($pconfig['step10']['dns4']))
		$server['dns_server4'] = $pconfig['step10']['dns4'];
	if (isset($pconfig['step10']['ntp1']))
		$server['ntp_server1'] = $pconfig['step10']['ntp1'];
	if (isset($pconfig['step10']['ntp2']))
		$server['ntp_server2'] = $pconfig['step10']['ntp2'];
	if (isset($pconfig['step10']['wins1']))
		$server['wins_server1'] = $pconfig['step10']['wins1'];
	if (isset($pconfig['step10']['wins2']))
		$server['wins_server2'] = $pconfig['step10']['wins2'];
	if (isset($pconfig['step10']['nbtenable'])) {
		$server['netbios_ntype'] = $pconfig['step10']['nbttype'];
		if (isset($pconfig['step10']['nbtscope'])) {
			$server['netbios_scope'] = $pconfig['step10']['nbtscope'];
		}

		$server['netbios_enable'] = $pconfig['step10']['nbtenable'];
	}
	return $server;
}
