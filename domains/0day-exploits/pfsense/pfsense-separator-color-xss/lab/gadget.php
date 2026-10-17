<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT firewall separator color class= gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9.
 * Priv page-firewall-rules / page-firewall-nat-portforward.
 */

ini_set('display_errors', '0');

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/filter.inc.excerpt.php';
require __DIR__ . '/pin-src/firewall_rules.php.excerpt.php';
require __DIR__ . '/pin-src/firewall_nat.inc.excerpt.php';

const WITNESS = 'PFSENSE-SEPARATOR-COLOR-XSS-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const COLUMNS_IN_TABLE = 13;
const IFACE = 'lan';

function reset_lab() {
	$GLOBALS['lab_config'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_headers'] = array();
	$GLOBALS['lab_dirty'] = array();
	$GLOBALS['lab_html'] = '';
	$GLOBALS['lab_filter_configure'] = 0;
	$_POST = array();
}

function send_json($status, $payload) {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	exit(0);
}

function send_text($status, $body, $ctype = 'text/plain; charset=utf-8') {
	http_response_code($status);
	header('Content-Type: ' . $ctype);
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

function request_str($key, $default = '') {
	if (isset($_POST[$key]) && is_string($_POST[$key])) {
		return $_POST[$key];
	}
	if (isset($_GET[$key]) && is_string($_GET[$key])) {
		return $_GET[$key];
	}
	$body = request_json();
	if (isset($body[$key]) && is_string($body[$key])) {
		return $body[$key];
	}
	return $default;
}

function request_row($default_row) {
	$body = request_json();
	if (isset($body['row'])) {
		if (is_array($body['row'])) {
			$out = array();
			foreach ($body['row'] as $item) {
				$out[] = strval($item);
			}
			return $out;
		}
		if (is_string($body['row'])) {
			return $body['row'];
		}
	}
	if (isset($_POST['row']) && is_string($_POST['row'])) {
		return $_POST['row'];
	}
	return $default_row;
}

function pin_source_blob() {
	$files = array(
		__DIR__ . '/pin-src/util.inc.excerpt.php',
		__DIR__ . '/pin-src/filter.inc.excerpt.php',
		__DIR__ . '/pin-src/firewall_rules.php.excerpt.php',
		__DIR__ . '/pin-src/firewall_nat.inc.excerpt.php',
		__DIR__ . '/pin-src/pfSenseHelpers.js.excerpt.js',
		__FILE__,
	);
	$parts = array();
	foreach ($files as $path) {
		$read = file_get_contents($path);
		if ($read === false) {
			return false;
		}
		$parts[] = $read;
	}
	return implode("\n", $parts);
}

function render_separators($separators, $nrules) {
	ob_start();
	display_separator($separators, $nrules, COLUMNS_IN_TABLE);
	$html = ob_get_clean();
	if (!is_string($html)) {
		$html = '';
	}
	$GLOBALS['lab_html'] = $html;
	return $html;
}

function build_post_separator($color, $text, $row, $iface) {
	return array(
		'row' => $row,
		'text' => $text,
		'color' => $color,
		'if' => $iface,
	);
}

function run_case($case, $page, $color, $text, $row, $nrules) {
	reset_lab();
	$_POST = array(
		'order-store' => 'store changes',
		'if' => IFACE,
		'separator' => array(
			0 => build_post_separator($color, $text, $row, IFACE),
		),
	);

	if ($page === 'nat') {
		reorderNATrules($_POST, true);
		$stored = config_get_path('nat/separator', array());
		$config_path = 'nat/separator';
	} else {
		firewall_rules_order_store(IFACE);
		$stored = config_get_path('filter/separator/' . strtolower(IFACE), array());
		$config_path = 'filter/separator/' . strtolower(IFACE);
	}

	$html = render_separators(is_array($stored) ? $stored : array(), $nrules);
	$seprows = separator_rows(is_array($stored) ? $stored : array());
	$encoded_text = htmlspecialchars($text);
	$stored_color = '';
	if (is_array($stored) && isset($stored['sep0']) && is_array($stored['sep0'])) {
		$stored_color = strval($stored['sep0']['color'] ?? '');
	}

	return array(
		'ok' => true,
		'case' => $case,
		'page' => $page,
		'privilege' => $page === 'nat'
			? 'page-firewall-nat-portforward'
			: 'page-firewall-rules',
		'nrules' => $nrules,
		'columns_in_table' => COLUMNS_IN_TABLE,
		'color' => $color,
		'text' => $text,
		'row' => $row,
		'row_is_array' => is_array($row),
		'stored_color' => $stored_color,
		'stored_path' => $config_path,
		'write_config' => (bool) $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'seprows' => $seprows,
		'html' => $html,
		'encoded_text' => $encoded_text,
		'class_control' => str_contains($html, 'class="bg-info"'),
		'witness_raw' => str_contains($html, WITNESS),
		'witness_attr' => str_contains($html, 'data-witness="' . WITNESS . '"'),
		'color_html_encoded' => str_contains($html, htmlspecialchars($color)),
		'text_raw_in_html' => str_contains($html, $text),
		'text_encoded_in_html' => $encoded_text !== '' && str_contains($html, $encoded_text),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping' || $path === '/health') {
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'page-firewall-rules',
		'nat_privilege' => 'page-firewall-nat-portforward',
		'witness' => WITNESS,
		'columns_in_table' => COLUMNS_IN_TABLE,
	));
}

if ($path === '/source') {
	$src = pin_source_blob();
	if ($src === false) {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, array(
		'html' => strval($GLOBALS['lab_html']),
		'witness' => WITNESS,
	));
}

if ($path === '/run') {
	$case = request_str('case');
	$page = request_str('page', 'rules');
	$color = request_str('color');
	$text = request_str('text', 'x');
	$row = request_row(array('fr0'));
	$nrules_raw = request_str('nrules', '0');
	$nrules = is_numeric($nrules_raw) ? intval($nrules_raw) : 0;
	if ($case === '') {
		send_json(400, array('error' => 'missing-case'));
	}
	if ($page !== 'rules' && $page !== 'nat') {
		send_json(400, array('error' => 'bad-page', 'page' => $page));
	}
	send_json(200, run_case($case, $page, $color, $text, $row, $nrules));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
