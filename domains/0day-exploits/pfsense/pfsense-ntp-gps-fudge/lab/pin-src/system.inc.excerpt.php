<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

global $ntp_poll_min_value, $ntp_poll_max_value;
global $ntp_poll_min_default_gps, $ntp_poll_max_default_gps;
global $ntp_poll_min_default_pps, $ntp_poll_max_default_pps;
global $ntp_poll_min_default, $ntp_poll_max_default;
$ntp_poll_min_value = 3;
$ntp_poll_max_value = 17;
$ntp_poll_min_default_gps = 4;
$ntp_poll_max_default_gps = 4;
$ntp_poll_min_default_pps = 4;
$ntp_poll_max_default_pps = 4;
$ntp_poll_min_default = 'omit';
$ntp_poll_max_default = 9;

function system_ntp_fixup_poll_value($type, $configvalue, $default) {
	$pollstring = "";

	if (empty($configvalue)) {
		$configvalue = $default;
	}

	if ($configvalue != 'omit') {
		$pollstring = " {$type} {$configvalue}";
	}

	return $pollstring;
}

function system_ntp_configure() {
	global $g;
	global $ntp_poll_min_default_gps, $ntp_poll_max_default_gps;
	global $ntp_poll_min_default_pps, $ntp_poll_max_default_pps;

	$ntpcfg = "# \n";
	$ntpcfg .= "# pfSense ntp configuration file \n";
	$ntpcfg .= "# \n\n";
	$ntpcfg .= "tinker panic 0 \n\n";

	/* Add PPS configuration */
	if (!empty(config_get_path('ntpd/pps/port')) &&
	    file_exists('/dev/'.config_get_path('ntpd/pps/port')) &&
	    system_ntp_setup_pps(config_get_path('ntpd/pps/port'))) {
		$ntpcfg .= "\n";
		$ntpcfg .= "# PPS Setup\n";
		$ntpcfg .= 'server 127.127.22.0';
		$ntpcfg .= system_ntp_fixup_poll_value('minpoll', config_get_path('ntpd/pps/ppsminpoll'), $ntp_poll_min_default_pps);
		$ntpcfg .= system_ntp_fixup_poll_value('maxpoll', config_get_path('ntpd/pps/ppsmaxpoll'), $ntp_poll_max_default_pps);
		if (empty(config_get_path('ntpd/pps/prefer'))) { /*note: this one works backwards */
			$ntpcfg .= ' prefer';
		}
		if (!empty(config_get_path('ntpd/pps/noselect'))) {
			$ntpcfg .= ' noselect ';
		}
		$ntpcfg .= "\n";
		$ntpcfg .= 'fudge 127.127.22.0';
		if (!empty(config_get_path('ntpd/pps/fudge1'))) {
			$ntpcfg .= ' time1 ';
			$ntpcfg .= config_get_path('ntpd/pps/fudge1');
		}
		if (!empty(config_get_path('ntpd/pps/flag2'))) {
			$ntpcfg .= ' flag2 1';
		}
		if (!empty(config_get_path('ntpd/pps/flag3'))) {
			$ntpcfg .= ' flag3 1';
		} else {
			$ntpcfg .= ' flag3 0';
		}
		if (!empty(config_get_path('ntpd/pps/flag4'))) {
			$ntpcfg .= ' flag4 1';
		}
		if (!empty(config_get_path('ntpd/pps/refid'))) {
			$ntpcfg .= ' refid ';
			$ntpcfg .= config_get_path('ntpd/pps/refid');
		}
		$ntpcfg .= "\n";
	}
	/* End PPS configuration */

	/* Add GPS configuration */
	if (!empty(config_get_path('ntpd/gps/port')) &&
	    system_ntp_setup_gps(config_get_path('ntpd/gps/port'))) {
		$ntpcfg .= "\n";
		$ntpcfg .= "# GPS Setup\n";
		$ntpcfg .= 'server 127.127.20.0 mode ';
		if (!empty(config_get_path('ntpd/gps/nmea')) || !empty(config_get_path('ntpd/gps/speed')) || !empty(config_get_path('ntpd/gps/subsec')) || !empty(config_get_path('ntpd/gps/processpgrmf'))) {
			if (!empty(config_get_path('ntpd/gps/nmea'))) {
				$ntpmode = (int) config_get_path('ntpd/gps/nmea');
			}
			if (!empty(config_get_path('ntpd/gps/speed'))) {
				$ntpmode += (int) config_get_path('ntpd/gps/speed');
			}
			if (!empty(config_get_path('ntpd/gps/subsec'))) {
				$ntpmode += 128;
			}
			if (!empty(config_get_path('ntpd/gps/processpgrmf'))) {
				$ntpmode += 256;
			}
			$ntpcfg .= (string) $ntpmode;
		} else {
			$ntpcfg .= '0';
		}
		$ntpcfg .= system_ntp_fixup_poll_value('minpoll', config_get_path('ntpd/gps/gpsminpoll'), $ntp_poll_min_default_gps);
		$ntpcfg .= system_ntp_fixup_poll_value('maxpoll', config_get_path('ntpd/gps/gpsmaxpoll'), $ntp_poll_max_default_gps);

		if (empty(config_get_path('ntpd/gps/prefer'))) { /*note: this one works backwards */
			$ntpcfg .= ' prefer';
		}
		if (!empty(config_get_path('ntpd/gps/noselect'))) {
			$ntpcfg .= ' noselect ';
		}
		$ntpcfg .= "\n";
		$ntpcfg .= 'fudge 127.127.20.0';
		if (!empty(config_get_path('ntpd/gps/fudge1'))) {
			$ntpcfg .= ' time1 ';
			$ntpcfg .= config_get_path('ntpd/gps/fudge1');
		}
		if (!empty(config_get_path('ntpd/gps/fudge2'))) {
			$ntpcfg .= ' time2 ';
			$ntpcfg .= config_get_path('ntpd/gps/fudge2');
		}
		if (!empty(config_get_path('ntpd/gps/flag1'))) {
			$ntpcfg .= ' flag1 1';
		} else {
			$ntpcfg .= ' flag1 0';
		}
		if (!empty(config_get_path('ntpd/gps/flag2'))) {
			$ntpcfg .= ' flag2 1';
		}
		if (!empty(config_get_path('ntpd/gps/flag3'))) {
			$ntpcfg .= ' flag3 1';
		} else {
			$ntpcfg .= ' flag3 0';
		}
		if (!empty(config_get_path('ntpd/gps/flag4'))) {
			$ntpcfg .= ' flag4 1';
		}
		if (!empty(config_get_path('ntpd/gps/refid'))) {
			$ntpcfg .= ' refid ';
			$ntpcfg .= config_get_path('ntpd/gps/refid');
		}
		if (!empty(config_get_path('ntpd/gps/stratum'))) {
			$ntpcfg .= ' stratum ';
			$ntpcfg .= config_get_path('ntpd/gps/stratum');
		}
		$ntpcfg .= "\n";
	} elseif (system_ntp_setup_gps(config_get_path('ntpd/gpsport'))) {
		/* This handles a 2.1 and earlier config */
		$ntpcfg .= "# GPS Setup\n";
		$ntpcfg .= "server 127.127.20.0 mode 0 minpoll 4 maxpoll 4 prefer\n";
		$ntpcfg .= "fudge 127.127.20.0 time1 0.155 time2 0.000 flag1 1 flag2 0 flag3 1\n";
		// Fall back to local clock if GPS is out of sync?
		$ntpcfg .= "server 127.127.1.0\n";
		$ntpcfg .= "fudge 127.127.1.0 stratum 12\n";
	}
	/* End GPS configuration */

	/* open configuration for writing or bail */
	if (!@file_put_contents("{$g['varetc_path']}/ntpd.conf", $ntpcfg)) {
		logger(LOG_ERR, localize_text("Could not open %s for writing", g_get('varetc_path') . '/ntpd.conf'), LOG_PREFIX_NTP);
		return;
	}

	/* start ntpd, set time now and use /var/etc/ntpd.conf */
	mwexec("/usr/local/sbin/ntpd -g -c {$g['varetc_path']}/ntpd.conf -p {$g['varrun_path']}/ntpd.pid", false, true);

	// Note that we are starting up
	logger(LOG_INFO, localize_text("NTPD is starting up."), LOG_PREFIX_NTP);

	return;
}
