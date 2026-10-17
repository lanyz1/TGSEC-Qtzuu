<?php
/*
 * Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand.
 *
##|+PRIV
##|*IDENT=page-services-dnsresolver-acls
##|*NAME=Services: DNS Resolver: Access Lists
##|*DESCR=Allow access to the 'Services: DNS Resolver: Access Lists' page.
##|*MATCH=services_unbound_acls.php*
##|-PRIV
 */

function unbound_acl_page_apply() {
	global $retval;
	$retval = 0;
	$retval |= services_unbound_configure();
	if ($retval == 0) {
		clear_subsystem_dirty('unbound');
	}
	return $retval;
}

function unbound_acl_page_save() {
	global $id, $input_errors, $networkacl;
	unset($input_errors);
	$pconfig = $_POST;
	$deleting = false;

	if (!is_array($networkacl)) {
		$networkacl = array();
	}

	// input validation - only allow 50 entries in a single ACL
	for ($x = 0; $x < 50; $x++) {
		if (isset($pconfig["acl_network{$x}"])) {
			$networkacl[$x] = array();
			$networkacl[$x]['acl_network'] = $pconfig["acl_network{$x}"];
			$networkacl[$x]['mask'] = $pconfig["mask{$x}"];
			$networkacl[$x]['description'] = $pconfig["description{$x}"];
			if (!is_ipaddr($networkacl[$x]['acl_network'])) {
				$input_errors[] = gettext("A valid IP address must be entered for each row under Networks.");
			}

			if (is_ipaddr($networkacl[$x]['acl_network'])) {
				if (!is_subnet($networkacl[$x]['acl_network']."/".$networkacl[$x]['mask'])) {
					$input_errors[] = gettext("A valid IPv4 netmask must be entered for each IPv4 row under Networks.");
				}
			} else if (function_exists("is_ipaddrv6")) {
				if (!is_ipaddrv6($networkacl[$x]['acl_network'])) {
					$input_errors[] = gettext("A valid IPv6 address must be entered for {$networkacl[$x]['acl_network']}.");
				} else if (!is_subnetv6($networkacl[$x]['acl_network']."/".$networkacl[$x]['mask'])) {
					$input_errors[] = gettext("A valid IPv6 netmask must be entered for each IPv6 row under Networks.");
				}
			} else {
				$input_errors[] = gettext("A valid IP address must be entered for each row under Networks.");
			}
		} else if (isset($networkacl[$x])) {
			unset($networkacl[$x]);
		}
	}

	if (!$input_errors) {
		if (strtolower($pconfig['save']) == strtolower(gettext("Save"))) {
			$acl_entry = array();
			$acl_entry['aclid'] = $pconfig['aclid'];
			$acl_entry['aclname'] = $pconfig['aclname'];
			$acl_entry['aclaction'] = $pconfig['aclaction'];
			$acl_entry['description'] = $pconfig['description'];
			$acl_entry['aclid'] = $pconfig['aclid'];
			$acl_entry['row'] = array();

			foreach ($networkacl as $acl) {
				$acl_entry['row'][] = $acl;
			}

			if (isset($id) && config_get_path('unbound/acls/' . $id)) {
				config_set_path('unbound/acls/' . $id, $acl_entry);
			} else {
				config_set_path('unbound/acls/' . count(config_get_path('unbound/acls', [])) + 1, $acl_entry);
			}

			mark_subsystem_dirty("unbound");
			write_config(gettext("Access list configured for DNS Resolver."));

			pfSenseHeader("/services_unbound_acls.php");
			return true;
		}
	}
	return false;
}
