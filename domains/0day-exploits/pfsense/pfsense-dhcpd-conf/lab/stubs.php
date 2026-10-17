<?php
/* Lab stubs for pin excerpts. mwexec records argv and does not exec. */

$g = array(
	'debug' => false,
	'booting' => false,
	'services_dhcp_server_enable' => true,
	'dhcpd_chroot_path' => '/lab/var/dhcpd',
	'varetc_path' => '/lab/var/etc',
	'varrun_path' => '/lab/var/run',
	'product_label' => 'pfSense',
	'product_version_string' => '2.9.0-DEVELOPMENT',
);

$config = array(
	'dhcpbackend' => 'isc',
	'dhcpd' => array(
		'lan' => array(
			'enable' => true,
			'range' => array(
				'from' => '192.0.2.100',
				'to' => '192.0.2.200',
			),
			'staticmap' => array(),
		),
	),
	'interfaces' => array(
		'lan' => array(
			'if' => 'em0',
			'ipaddr' => '192.0.2.1',
			'subnet' => '24',
			'enable' => true,
		),
	),
	'system' => array(
		'hostname' => 'lab',
		'domain' => 'example.test',
		'dnsserver' => array('192.0.2.53'),
	),
);

$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_dirty'] = array();

function gettext($text) {
	return $text;
}

function g_get(string $key, mixed $default = null): mixed {
	global $g;
	return array_key_exists($key, $g) ? $g[$key] : $default;
}

function is_platform_booting(): bool {
	return false;
}

function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	$GLOBALS['lab_mwexec'][] = $command;
	return 0;
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function mark_subsystem_dirty($subsystem) {
	$GLOBALS['lab_dirty'][] = $subsystem;
}

function staticmaps_sort($ifgui) {
	$dhcpd_config = config_get_path("dhcpd/{$ifgui}/staticmap");
	if (!is_array($dhcpd_config)) {
		return;
	}
	config_set_path("dhcpd/{$ifgui}/staticmap", array_values($dhcpd_config));
}

function get_real_interface($interface, $family = 'all') {
	if ($interface === 'lan') {
		return 'em0';
	}
	return $interface;
}

function dhcp_get_backend() {
	$dhcpbackend = config_get_path('dhcpbackend');
	return (in_array($dhcpbackend, ['isc', 'kea']) ? $dhcpbackend : 'isc');
}

function dhcp_is_backend($dhcpbackend) {
	return (dhcp_get_backend() === $dhcpbackend);
}

function is_dhcp_server_enabled() {
	foreach (config_get_path('dhcpd', []) as $dhcpif => $dhcpifconf) {
		if (empty($dhcpifconf)) {
			continue;
		}
		if (isset($dhcpifconf['enable']) &&
			!empty(config_get_path("interfaces/{$dhcpif}"))) {
			return true;
		}
	}

	return false;
}

function is_ipaddrv4($ip) {
	if (!is_string($ip) || $ip === '') {
		return false;
	}
	return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

function is_unqualified_hostname($hostname) {
	if (!is_string($hostname)) {
		return false;
	}

	if (preg_match('/^(?:[a-z0-9_]|[a-z0-9_][a-z0-9_\-]*[a-z0-9_])$/i', $hostname)) {
		return true;
	} else {
		return false;
	}
}

function is_domain($domain, $allow_wildcard = false, $trailing_dot = true) {
	if (!is_string($domain)) {
		return false;
	}
	if (!$trailing_dot && ($domain[strlen($domain) - 1] == ".")) {
		return false;
	}
	if ($allow_wildcard) {
		$domain_regex = '/^(?:(?:[a-z_0-9\*]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$/i';
	} else {
		$domain_regex = '/^(?:(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9])\.)*(?:[a-z_0-9]|[a-z_0-9][a-z_0-9\-]*[a-z_0-9\.])$/i';
	}

	if (preg_match($domain_regex, $domain)) {
		return true;
	} else {
		return false;
	}
}

function is_hostname($hostname, $allow_wildcard = false) {
	if (!is_string($hostname)) {
		return false;
	}

	if (is_domain($hostname, $allow_wildcard)) {
		if ((substr_count($hostname, ".") == 1) && ($hostname[strlen($hostname) - 1] == ".")) {
			return false;
		} else {
			return true;
		}
	} else {
		return false;
	}
}

function is_macaddr($macaddr, $partial = false) {
	if (!is_string($macaddr) || $macaddr === '') {
		return false;
	}
	$values = explode(":", $macaddr);
	if ($partial) {
		if ((count($values) < 1) || (count($values) > 6)) {
			return false;
		}
	} elseif (count($values) != 6) {
		return false;
	}
	foreach ($values as $value) {
		if (!preg_match('/^[0-9a-f]{1,2}$/i', $value)) {
			return false;
		}
	}
	return true;
}

function array_get_path(array &$arr, string $path, $default = null) {
	$vpath = explode('/', $path);
	$el = $arr;
	foreach ($vpath as $key) {
		if (mb_strlen($key) == 0) {
			continue;
		}
		if (is_array($el) && array_key_exists($key, $el)) {
			$el = $el[$key];
		} else {
			return ($default);
		}
	}

	if (($default !== null) && ($el === '')) {
		return ($default);
	}

	return ($el);
}

function array_set_path(array &$arr, string $path, $value, $default = null) {
	$vpath = explode('/', $path);
	if (($path != '') && ($vpath[array_key_last($vpath)] === '')) {
		$append = true;
	} else {
		$append = false;
	}

	do {
		$vkey = array_pop($vpath);
	} while (isset($vkey) && (mb_strlen($vkey) == 0));

	if ($vkey == null) {
		if ($append) {
			$arr[] = (is_array($value)) ? $value : [$value];
		} else {
			$arr = (is_array($value)) ? $value : [$value];
		}
		return ($value);
	}

	$el =& $arr;
	foreach ($vpath as $key) {
		if (mb_strlen($key) == 0) {
			continue;
		}
		if (array_key_exists($key, $el) && !empty($el[$key])) {
			if (!is_array($el[$key])) {
				return ($default);
			}
		} else {
			$el[$key] = [];
		}
		$el =& $el[$key];
	}

	if ($append) {
		if (is_array($el[$vkey] ?? null)) {
			$el[$vkey][] = $value;
		} else {
			$el[$vkey] = [$value];
		}
	} else {
		$el[$vkey] = $value;
	}

	return ($value);
}

function array_path_enabled(array &$arr, string $path, $enable_key = "enable", $default = false) {
	$el = array_get_path($arr, $path, $default);
	return is_array($el) ? isset($el[$enable_key]) : $default;
}

function config_get_path(string $path, $default = null) {
	global $config;
	return is_array($config) ? array_get_path($config, $path, $default) : $default;
}

function config_set_path(string $path, $value, $default = null) {
	global $config;
	return is_array($config) ? array_set_path($config, $path, $value, $default) : $default;
}

function config_path_enabled(string $path, $enable_key = "enable", $default = false) {
	global $config;
	return is_array($config) ? array_path_enabled($config, $path, $enable_key, $default) : $default;
}

function do_input_validation($postdata, $reqdfields, $reqdfieldsn, &$input_errors) {
	if (!is_array($input_errors)) {
		$input_errors = array();
	}
	for ($i = 0; $i < count($reqdfields); $i++) {
		$field = $reqdfields[$i];
		if (!isset($postdata[$field]) || $postdata[$field] === '') {
			$name = $reqdfieldsn[$i] ?? $field;
			$input_errors[] = sprintf("%s is required.", $name);
		}
	}
}
