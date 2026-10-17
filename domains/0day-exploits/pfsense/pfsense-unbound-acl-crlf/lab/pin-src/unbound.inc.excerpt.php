<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function create_unbound_chroot_path($cfgsubdir = "") {
	global $g;

	// Configure chroot
	if (!is_dir(g_get('unbound_chroot_path'))) {
		mkdir(g_get('unbound_chroot_path'));
		chown(g_get('unbound_chroot_path'), "unbound");
		chgrp(g_get('unbound_chroot_path'), "unbound");
	}

	if ($cfgsubdir != "") {
		$cfgdir = g_get('unbound_chroot_path') . $cfgsubdir;
		if (!is_dir($cfgdir)) {
			mkdir($cfgdir);
			chown($cfgdir, "unbound");
			chgrp($cfgdir, "unbound");
		}
	}
}

function unbound_access_lists_include_line($cfgsubdir = "") {
	global $g;
	return "include: {$g['unbound_chroot_path']}{$cfgsubdir}/access_lists.conf";
}

function do_as_unbound_user($cmd, $param1 = "") {
	global $g;

	switch ($cmd) {
		case "start":
			mwexec("/usr/local/sbin/unbound -c {$g['unbound_chroot_path']}/unbound.conf");
			break;
		case "stop":
			mwexec("/usr/bin/su -m unbound -c '/usr/local/sbin/unbound-control -c {$g['unbound_chroot_path']}/unbound.conf stop'", true);
			break;
		case "reload":
			mwexec("/usr/bin/su -m unbound -c '/usr/local/sbin/unbound-control -c {$g['unbound_chroot_path']}/unbound.conf reload'", true);
			break;
		default:
			break;
	}
}

function unbound_acls_config($cfgsubdir = "") {
	global $g;

	/* Lab: skip auto-added ACLs (disable_auto_added_access_control). Custom name/action writer is pin. */
	$aclcfg = "";

	// Configure the custom ACLs
	foreach (config_get_path('unbound/acls', []) as $unbound_acl) {
		$aclcfg .= "#{$unbound_acl['aclname']}\n";
		foreach ($unbound_acl['row'] as $network) {
			switch ($unbound_acl['aclaction']) {
				case 'allow snoop':
					$action = 'allow_snoop';
					break;
				case 'deny nonlocal':
					$action = 'deny_non_local';
					break;
				case 'refuse nonlocal':
					$action = 'refuse_non_local';
					break;
				default:
					$action = $unbound_acl['aclaction'];
			}
			$aclcfg .= "access-control: {$network['acl_network']}/{$network['mask']} {$action}\n";
		}
	}
	// Write out Access list
	create_unbound_chroot_path($cfgsubdir);
	file_put_contents("{$g['unbound_chroot_path']}{$cfgsubdir}/access_lists.conf", $aclcfg);

}
