<?php
/* Lab stubs for pin excerpts. $portlist hides live lagg members and ovpn tun. */

if (!defined('LOG_INFO')) {
	define('LOG_INFO', 6);
}
if (!defined('LOG_ERR')) {
	define('LOG_ERR', 3);
}
if (!defined('LOG_DEBUG')) {
	define('LOG_DEBUG', 7);
}
if (!defined('IFCAP_VLAN_HWTAGGING')) {
	define('IFCAP_VLAN_HWTAGGING', 1);
}
if (!defined('IFCAP_VLAN_MTU')) {
	define('IFCAP_VLAN_MTU', 2);
}
if (!defined('IFCAP_VLAN_HWFILTER')) {
	define('IFCAP_VLAN_HWFILTER', 4);
}

$GLOBALS['lab_live_ifs'] = array();
$GLOBALS['lab_interface_list'] = array();
$GLOBALS['lab_lagg_list'] = array();
$GLOBALS['lab_logs'] = array();
$GLOBALS['lab_write_config'] = false;
$GLOBALS['lab_write_desc'] = '';
$GLOBALS['lab_mwexec'] = array();
$GLOBALS['lab_bring_up'] = array();
$GLOBALS['lab_configure'] = array();
$GLOBALS['lab_vlan'] = null;
$GLOBALS['lab_vlanif'] = null;
$GLOBALS['lab_vlan_create'] = array();

$config = array();
$portlist = array();
$input_errors = array();

function lab_reset_state() {
	global $config, $portlist, $input_errors;

	$GLOBALS['lab_live_ifs'] = array('em0', 'em1', 'lagg0', 'ovpns1');
	$GLOBALS['lab_interface_list'] = array(
		'em0' => array('mac' => '00:00:00:00:00:01'),
		'em1' => array('mac' => '00:00:00:00:00:02'),
		'ovpns1' => array('mac' => '00:00:00:00:00:03'),
	);
	$GLOBALS['lab_lagg_list'] = array(
		'lagg0' => array(
			'members' => 'em1',
			'laggif' => 'lagg0',
			'mac' => '00:00:00:00:00:10',
			'islagg' => true,
		),
	);
	$GLOBALS['lab_logs'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_mwexec'] = array();
	$GLOBALS['lab_bring_up'] = array();
	$GLOBALS['lab_configure'] = array();
	$GLOBALS['lab_vlan'] = null;
	$GLOBALS['lab_vlanif'] = null;
	$GLOBALS['lab_vlan_create'] = array();
	$config = array(
		'openvpn' => array(
			'openvpn-server' => array(
				array(
					'vpnid' => '1',
					'dev_mode' => 'tun',
				),
			),
		),
		'vlans' => array(
			'vlan' => array(),
		),
		'qinqs' => array(
			'qinqentry' => array(),
		),
		'interfaces' => array(),
	);
	$portlist = array();
	$input_errors = array();
}

function gettext($text) {
	return $text;
}

function localize_text($text, ...$args) {
	if (count($args) === 0) {
		return $text;
	}
	return vsprintf($text, $args);
}

function logger($priority, $message) {
	$GLOBALS['lab_logs'][] = array(
		'priority' => $priority,
		'message' => $message,
	);
}

function does_interface_exist($interface, $flush = false) {
	if (!$interface) {
		return false;
	}
	return in_array($interface, $GLOBALS['lab_live_ifs'], true);
}

function get_interface_arr($flush = false) {
	return $GLOBALS['lab_live_ifs'];
}

function get_interface_list($mode = "active", $keyby = "physical", $vfaces = false) {
	return $GLOBALS['lab_interface_list'];
}

function get_lagg_interface_list() {
	return $GLOBALS['lab_lagg_list'];
}

function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
	$GLOBALS['lab_write_config'] = true;
	$GLOBALS['lab_write_desc'] = $desc;
}

function mwexec($command, $nologentry = false) {
	$GLOBALS['lab_mwexec'][] = $command;
	exec($command);
	return 0;
}

function interfaces_bring_up($interface) {
	$GLOBALS['lab_bring_up'][] = $interface;
}

function interface_configure($interface, $reload = false, $linkupevent = false, $skip_parent_mtu = false) {
	$GLOBALS['lab_configure'][] = $interface;
}

function convert_real_interface_to_friendly_interface_name($interface) {
	return null;
}

function interface_vlan_mtu_configured($vlanif) {
	return 0;
}

function set_interface_mtu($interface, $mtu) {
	return true;
}

function pfSense_interface_capabilities($if, $caps) {
	return true;
}

function pfSense_interface_destroy($realif) {
	return true;
}

function pfSense_interface_create2($if) {
	return 'vlan0';
}

function pfSense_interface_rename($old, $new) {
	return true;
}

function pfSense_ngctl_name($old, $new) {
	return true;
}

/* Lab model of pfSense_vlan_create: ioctl on parent, not a shell. */
function pfSense_vlan_create($vlanif, $if, $tag, $pcp) {
	$GLOBALS['lab_vlan_create'][] = array(
		'vlanif' => $vlanif,
		'if' => $if,
		'tag' => $tag,
		'pcp' => $pcp,
	);
	$command = '/sbin/ifconfig vlan create vlandev ' . escapeshellarg($if) .
		' vlan ' . escapeshellarg((string)$tag) .
		' name ' . escapeshellarg($vlanif);
	mwexec($command);
	return 0;
}

function do_input_validation($postdata, $reqdfields, $reqdfieldsn, &$input_errors) {
	foreach ($postdata as $pn => $pd) {
		if (is_string($pd) && preg_match("/[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]/", $pd)) {
			$input_errors[] = sprintf(gettext("The field %s contains invalid characters."), $pn);
		}
	}

	if (is_array($reqdfields)) {
		for ($i = 0; $i < count($reqdfields); $i++) {
			if ($postdata[$reqdfields[$i]] == "") {
				$input_errors[] = sprintf(gettext("The field %s is required."), $reqdfieldsn[$i]);
			}
		}
	}
}

function array_get_path(array &$arr, string $path, $default = null) {
	$vpath = explode('/', $path);
	$el = $arr;
	foreach ($vpath as $key) {
		if (strlen($key) == 0) {
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
		if (is_array($el[$vkey])) {
			$el[$vkey][] = $value;
		} else {
			$el[$vkey] = [$value];
		}
	} else {
		$el[$vkey] = $value;
	}

	return ($value);
}

function config_get_path(string $path, $default = null) {
	global $config;
	if (!is_array($config)) {
		return $default;
	}
	if ($path === '' || $path === '/') {
		return $config;
	}
	return array_get_path($config, $path, $default);
}

function config_set_path(string $path, $value, $default = null) {
	global $config;
	if (!is_array($config)) {
		$config = array();
	}
	if ($path === '') {
		if (!is_array($value)) {
			return $default;
		}
		$config = $value;
		return $value;
	}
	return array_set_path($config, $path, $value, $default);
}

function config_path_enabled(string $path, $enable_key = "enable", $default = false) {
	$arr = config_get_path($path, null);
	if (!is_array($arr)) {
		return $default;
	}
	return array_key_exists($enable_key, $arr) && $arr[$enable_key] !== null;
}
