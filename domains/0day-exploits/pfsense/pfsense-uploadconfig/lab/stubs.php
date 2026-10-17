<?php
/* Lab stubs for pin uploadconfig.php. config_install copies the blob; system_reboot records the flag. */

const WITNESS = 'PFSENSE-UPLOADCONFIG-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-UPLOADCONFIG-WITNESS';
const STATE_PATH = '/oracle/state.json';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const PRIVILEGE = 'page-hidden-uploadconfiguration';

$g = array(
	'tmp_path' => '/lab/tmp',
	'conf_path' => '/lab/conf',
);

$priv_list = array();
$GLOBALS['lab_install_called'] = false;
$GLOBALS['lab_reboot_requested'] = false;
$GLOBALS['lab_install_src'] = '';
$GLOBALS['lab_install_blob'] = '';

function gettext($text) {
	return $text;
}

function lab_conf_path() {
	global $g;
	return $g['conf_path'] . '/config.xml';
}

function lab_tmp_config_path() {
	global $g;
	return $g['tmp_path'] . '/config.xml';
}

function lab_write_state() {
	$conf = lab_conf_path();
	$blob = is_file($conf) ? (string) file_get_contents($conf) : '';
	$payload = array(
		'install_called' => (bool) $GLOBALS['lab_install_called'],
		'reboot_requested' => (bool) $GLOBALS['lab_reboot_requested'],
		'install_src' => (string) $GLOBALS['lab_install_src'],
		'blob' => $blob,
		'conf_path' => $conf,
	);
	file_put_contents(STATE_PATH, json_encode($payload, JSON_UNESCAPED_SLASHES));
}

function lab_read_state() {
	if (!is_file(STATE_PATH)) {
		return array(
			'install_called' => false,
			'reboot_requested' => false,
			'install_src' => '',
			'blob' => '',
			'conf_path' => lab_conf_path(),
		);
	}
	$decoded = json_decode((string) file_get_contents(STATE_PATH), true);
	if (!is_array($decoded)) {
		return array(
			'install_called' => false,
			'reboot_requested' => false,
			'install_src' => '',
			'blob' => '',
			'conf_path' => lab_conf_path(),
		);
	}
	return $decoded;
}

function lab_reset() {
	$GLOBALS['lab_install_called'] = false;
	$GLOBALS['lab_reboot_requested'] = false;
	$GLOBALS['lab_install_src'] = '';
	$GLOBALS['lab_install_blob'] = '';
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
	if (is_file(STATE_PATH)) {
		unlink(STATE_PATH);
	}
	$conf = lab_conf_path();
	if (is_file($conf)) {
		unlink($conf);
	}
	$tmp = lab_tmp_config_path();
	if (is_file($tmp)) {
		unlink($tmp);
	}
	lab_write_state();
}

function lab_maybe_witness() {
	if ($GLOBALS['lab_install_called'] && $GLOBALS['lab_reboot_requested']) {
		file_put_contents(WITNESS_PATH, WITNESS . "\n");
	}
}

function witness_state() {
	$exists = is_file(WITNESS_PATH);
	$body = '';
	if ($exists) {
		$read = file_get_contents(WITNESS_PATH);
		$body = ($read === false) ? '' : $read;
	}
	return array(
		'exists' => $exists,
		'present' => $exists,
		'body' => $body,
		'path' => WITNESS_PATH,
	);
}

function config_install($conffile) {
	global $g;

	$GLOBALS['lab_install_called'] = true;
	$GLOBALS['lab_install_src'] = is_string($conffile) ? $conffile : '';
	if (!is_string($conffile) || $conffile === '' || !file_exists($conffile)) {
		lab_write_state();
		return 1;
	}
	$blob = file_get_contents($conffile);
	if ($blob === false) {
		lab_write_state();
		return 1;
	}
	$GLOBALS['lab_install_blob'] = $blob;
	$dest = $g['conf_path'] . '/config.xml';
	if (file_put_contents($dest, $blob) === false) {
		lab_write_state();
		return 1;
	}
	lab_write_state();
	return 0;
}

function system_reboot() {
	$GLOBALS['lab_reboot_requested'] = true;
	lab_maybe_witness();
	lab_write_state();
}
