<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function voucher_expire($voucher_received, $carp_loop = false) {
	global $g, $cpzone, $cpzoneid;

	$voucherlck = lock("voucher{$cpzone}", LOCK_EX);

	// split into an array. Useful for multiple vouchers given
	$a_vouchers_received = preg_split("/[\t\n\r ]+/s", $voucher_received);
	$unsetindexes = array();

	// go through all received vouchers, check their valid and extract
	// Roll# and Ticket# using the external readvoucher binary
	foreach ($a_vouchers_received as $voucher) {
		$v = escapeshellarg($voucher);
		if (strlen($voucher) < 5) {
			captiveportal_syslog("{$voucher} invalid: Too short!");
			continue;   // seems too short to be a voucher!
		}

		/* Lab: /usr/local/bin/voucher is stubbed OK so the SQL sink is reached. */
		unset($output);
		$_gb = exec("/usr/local/bin/voucher -c {$g['varetc_path']}/voucher_{$cpzone}.cfg -k {$g['varetc_path']}/voucher_{$cpzone}.public -- $v", $output);
		list($status, $roll, $nr) = explode(" ", $output[0]);
		if ($status == "OK") {
			captiveportal_syslog("{$voucher} ({$roll}/{$nr}) forced to expire");

			/* Check if this voucher has any active sessions */
			$cpentry = captiveportal_read_db("WHERE username = '{$voucher}'");
			if (!empty($cpentry) && !empty($cpentry[0])) {
				if (empty($cpzoneid) && !empty(config_get_path("captiveportal/{$cpzone}"))) {
					$cpzoneid = config_get_path("captiveportal/{$cpzone}/zoneid");
				}
				$cpentry = $cpentry[0];
				captiveportal_disconnect($cpentry, 13);
				captiveportal_logportalauth($cpentry[4], $cpentry[3], $cpentry[2], "FORCEFULLY TERMINATING VOUCHER {$voucher} SESSION");
				$unsetindexes[] = $cpentry[5];
			}
		} else {
			captiveportal_syslog(sprintf(gettext('%1$s invalid: %2$s!!'), $voucher, $output[0]));
		}
	}

	unlock($voucherlck);

	/* Write database */
	if (!empty($unsetindexes)) {
		captiveportal_remove_entries($unsetindexes);
	}

	return true;
}
