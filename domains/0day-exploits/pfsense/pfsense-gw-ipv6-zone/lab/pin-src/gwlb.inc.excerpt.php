<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function return_dpinger_defaults() {
	return array(
		"latencylow" => "200",
		"latencyhigh" => "500",
		"losslow" => "10",
		"losshigh" => "20",
		"interval" => "500",
		"loss_interval" => "2000",
		"time_period" => "60000",
		"alert_interval" => "1000",
		"data_payload" => "1");
}

function start_dpinger($gateway) {
	if (!isset($gateway['gwifip'])) {
		return (false);
	}

	$dpinger_defaults = return_dpinger_defaults();

	$prefix = g_get('varrun_path', '') . "/dpinger_{$gateway['name']}~" .
	    "{$gateway['gwifip']}~{$gateway['monitor']}";
	# dpinger socket path should not be longer then uaddr.sun_path
	if (strlen($prefix) > 95) {
		$prefix = g_get('varrun_path', '') . "/dpinger_{$gateway['name']}~" .
		    substr(md5($gateway['gwifip']),0,8) . "~" .
		    $gateway['monitor'];
	}
	$pidfile = $prefix . ".pid";
	$socket = $prefix . ".sock";
	$alarm_cmd = g_get('etc_path', '') . '/rc.gateway_alarm';

	$params  = "-S ";			/* Log warnings via syslog */
	$params .= "-r 0 ";			/* Disable unused reporting thread */
	$params .= "-i {$gateway['name']} ";	/* Identifier */
	$params .= "-B {$gateway['gwifip']} ";	/* Bind src address */
	$params .= "-p {$pidfile} ";		/* PID filename */
	$params .= "-u {$socket} ";		/* Status Socket */
	if (!$gateway['action_disable']) {
		$params .= "-C \"{$alarm_cmd}\" ";	/* Command to run on alarm */
	}

	$params .= "-d " .
	    (isset($gateway['data_payload']) && is_numeric($gateway['data_payload'])
	    ? $gateway['data_payload']
	    : $dpinger_defaults['data_payload']
	    ) . " ";

	$params .= "-s " .
	    (isset($gateway['interval']) && is_numeric($gateway['interval'])
	    ? $gateway['interval']
	    : $dpinger_defaults['interval']
	    ) . " ";

	$params .= "-l " .
	    (isset($gateway['loss_interval']) && is_numeric($gateway['loss_interval'])
	    ?  $gateway['loss_interval']
	    : $dpinger_defaults['loss_interval']
	    ) . " ";

	$params .= "-t " .
	    (isset($gateway['time_period']) && is_numeric($gateway['time_period'])
	    ?  $gateway['time_period']
	    : $dpinger_defaults['time_period']
	    ) . " ";

	$params .= "-A " .
	    (isset($gateway['alert_interval']) && is_numeric($gateway['alert_interval'])
	    ?  $gateway['alert_interval']
	    : $dpinger_defaults['alert_interval']
	    ) . " ";

	$params .= "-D " .
	    (isset($gateway['latencyhigh']) && is_numeric($gateway['latencyhigh'])
	    ?  $gateway['latencyhigh']
	    : $dpinger_defaults['latencyhigh']
	    ) . " ";

	$params .= "-L " .
	    (isset($gateway['losshigh']) && is_numeric($gateway['losshigh'])
	    ?  $gateway['losshigh']
	    : $dpinger_defaults['losshigh']
	    ) . " ";

	/* Make sure we don't end up with 2 process for the same GW */
	stop_dpinger($gateway['name']);

	/* Do not try to bind IPv6 where interface is in tentative state */
	if (is_ipaddrv6($gateway['gwifip'])) {
		$err = interface_wait_tentative(get_real_interface(
		    $gateway['interface']));
		if ($err == false) {
			logger(LOG_ERR, localize_text("Timeout waiting for IPv6 address in tentative state.  dpinger will not run."), LOG_PREFIX_GWMON);
			return (false);
		}
	}

	/* Redirect stdout to /dev/null to avoid exec() to wait for dpinger */
	return mwexec("/usr/local/bin/dpinger {$params} {$gateway['monitor']} >/dev/null");
}
