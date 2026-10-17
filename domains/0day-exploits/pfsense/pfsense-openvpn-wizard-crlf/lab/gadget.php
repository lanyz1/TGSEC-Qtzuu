<?php
declare(strict_types=1);

/**
 * Loopback gadget for pfSense OpenVPN wizard defaultdomain / nbtscope CRLF.
 * Calls pinned openvpn_add_dhcpopts after the wizard step-10 assignment.
 * Does not boot pfSense. Oracle is /oracle/PFSENSE-OPENVPN-WIZARD-CRLF-WITNESS.
 */

const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const WITNESS_NAME = 'PFSENSE-OPENVPN-WIZARD-CRLF-WITNESS';
const WITNESS_PATH = '/oracle/' . WITNESS_NAME;
const WRITER_PATH = '/oracle/write-witness.sh';
const SCRIPT_SECURITY_3 = "script-security 3\n";

error_reporting(E_ALL);
ini_set('display_errors', '0');

function is_ipaddrv6($ip) {
	if (!is_string($ip) || $ip === '') {
		return false;
	}
	return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

require __DIR__ . '/pin/openvpn_add_dhcpopts.inc';
require __DIR__ . '/pin/wizard_assign.inc';

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

try {
	route($path);
} catch (Throwable $exc) {
	send_json(500, [
		'error' => $exc->getMessage(),
		'class' => $exc::class,
	]);
}

function route(string $path): void
{
	if ($path === '/ping') {
		send_json(200, [
			'ok' => true,
			'pong' => 'pong',
			'pin' => PIN_SHA,
			'openvpn' => openvpn_version(),
		]);
	}

	if ($path === '/pin/dhcpopts') {
		send_text(200, pin_file('openvpn_add_dhcpopts.inc'));
	}
	if ($path === '/pin/wizard') {
		send_text(200, pin_file('wizard_assign.inc'));
	}

	if ($path === '/generate') {
		send_json(200, generate_from_request());
	}

	if ($path === '/exec') {
		send_json(200, exec_server_conf());
	}

	if ($path === '/oracle') {
		send_json(200, oracle_status());
	}

	if ($path === '/oracle/harness-write') {
		send_json(200, harness_write());
	}

	send_json(404, ['error' => 'not-found', 'path' => $path]);
}

function pin_file(string $name): string
{
	$full = __DIR__ . '/pin/' . $name;
	$body = file_get_contents($full);
	if ($body === false) {
		throw new RuntimeException('pin-file-missing ' . $name);
	}
	return $body;
}

function openvpn_version(): string
{
	$out = [];
	$rc = 0;
	exec('openvpn --version 2>&1', $out, $rc);
	return $out[0] ?? '';
}

function read_input(): array
{
	$raw = file_get_contents('php://input');
	if (is_string($raw) && $raw !== '') {
		$data = json_decode($raw, true);
		if (is_array($data)) {
			return $data;
		}
	}
	return $_GET;
}

function str_field(array $data, string $key): string
{
	$value = $data[$key] ?? '';
	return is_string($value) ? $value : '';
}

function generate_from_request(): array
{
	$data = read_input();
	$kind = str_field($data, 'kind');
	if ($kind === '') {
		$kind = 'server';
	}
	return generate_conf(
		$kind,
		str_field($data, 'defaultdomain'),
		str_field($data, 'nbtscope'),
		!empty($data['nbtenable'])
	);
}

function generate_conf(string $kind, string $defaultdomain, string $nbtscope, bool $nbtenable): array
{
	$pconfig = ['step10' => []];
	if ($defaultdomain !== '') {
		$pconfig['step10']['defaultdomain'] = $defaultdomain;
	}
	if ($nbtenable || $nbtscope !== '') {
		$pconfig['step10']['nbtenable'] = 'on';
		$pconfig['step10']['nbttype'] = '0';
		if ($nbtscope !== '') {
			$pconfig['step10']['nbtscope'] = $nbtscope;
		}
	}

	$server = wizard_copy_step10($pconfig);
	foreach (['netbios_enable', 'gwredir', 'gwredir6'] as $key) {
		if (!array_key_exists($key, $server)) {
			$server[$key] = '';
		}
	}

	$dhcpopts = '';
	openvpn_add_dhcpopts($server, $dhcpopts);

	$wizard_assign = array_key_exists('dns_domain', $server)
		&& $server['dns_domain'] === ($pconfig['step10']['defaultdomain'] ?? null);

	if ($kind === 'ccd') {
		return [
			'kind' => 'ccd',
			'pin' => PIN_SHA,
			'wizard_assign' => $wizard_assign,
			'dns_domain_set' => array_key_exists('dns_domain', $server),
			'netbios_scope_set' => array_key_exists('netbios_scope', $server),
			'dhcpopts' => $dhcpopts,
			'conf' => $dhcpopts,
			'script_security_3' => false,
			'ccd_executes_up' => false,
			'ccd_up_ignored' => true,
			'note' => 'OpenVPN CCD allows push/iroute/ifconfig-push/config/disable; up is not executed. This blob is not fed as a server --config.',
		];
	}

	$conf = SCRIPT_SECURITY_3 . $dhcpopts;
	return [
		'kind' => 'server',
		'pin' => PIN_SHA,
		'wizard_assign' => $wizard_assign,
		'dns_domain_set' => array_key_exists('dns_domain', $server),
		'netbios_scope_set' => array_key_exists('netbios_scope', $server),
		'dhcpopts' => $dhcpopts,
		'conf' => $conf,
		'script_security_3' => str_contains($conf, 'script-security 3'),
		'full_conf_tun' => server_prefix('tun') . $conf,
		'full_conf_null' => server_prefix('null') . $conf,
	];
}

function server_prefix(string $dev): string
{
	$lines = [
		'local 127.0.0.1',
		'lport 11940',
		'proto udp',
		'dev ' . $dev,
		'topology subnet',
		'verb 3',
		'persist-tun',
		'ca /lab/pki/cert.pem',
		'cert /lab/pki/cert.pem',
		'key /lab/pki/key.pem',
		'dh none',
		'ecdh-curve prime256v1',
	];
	if ($dev === 'tun') {
		$lines[] = 'server 10.8.0.0 255.255.255.0';
	} else {
		$lines[] = 'mode server';
		$lines[] = 'tls-server';
		$lines[] = 'ifconfig 10.8.0.1 255.255.255.0';
	}
	return implode("\n", $lines) . "\n";
}

function exec_server_conf(): array
{
	$data = read_input();
	$generated = generate_conf(
		'server',
		str_field($data, 'defaultdomain'),
		str_field($data, 'nbtscope'),
		!empty($data['nbtenable'])
	);

	@unlink(WITNESS_PATH);
	ensure_writer();

	$attempts = [
		['dev' => 'tun', 'conf' => $generated['full_conf_tun']],
		['dev' => 'null', 'conf' => $generated['full_conf_null']],
	];
	$runs = [];
	$up_exec = false;
	$used_dev = '';
	foreach ($attempts as $attempt) {
		$result = run_openvpn($attempt['conf'], $attempt['dev']);
		$runs[] = $result;
		if (!empty($result['witness_exists'])) {
			$up_exec = true;
			$used_dev = $attempt['dev'];
			break;
		}
	}

	return [
		'kind' => 'exec',
		'pin' => PIN_SHA,
		'wizard_assign' => $generated['wizard_assign'],
		'conf' => $generated['conf'],
		'dhcpopts' => $generated['dhcpopts'],
		'script_security_3' => $generated['script_security_3'],
		'up_exec' => $up_exec,
		'used_dev' => $used_dev,
		'witness_exists' => is_file(WITNESS_PATH),
		'witness_body' => witness_body(),
		'runs' => $runs,
	];
}

function ensure_writer(): void
{
	if (!is_file(WRITER_PATH)) {
		file_put_contents(
			WRITER_PATH,
			"#!/bin/sh\nprintf '%s\\n' '" . WITNESS_NAME . "' > " . WITNESS_PATH . "\n"
		);
	}
	chmod(WRITER_PATH, 0755);
}

function run_openvpn(string $conf, string $dev): array
{
	$path = '/tmp/lab-server-' . $dev . '.ovpn';
	file_put_contents($path, $conf);

	$cmd = ['openvpn', '--disable-dco', '--config', $path];
	$descriptors = [
		0 => ['pipe', 'r'],
		1 => ['pipe', 'w'],
		2 => ['pipe', 'w'],
	];
	$proc = proc_open($cmd, $descriptors, $pipes, '/tmp', null);
	if (!is_resource($proc)) {
		return [
			'dev' => $dev,
			'error' => 'proc-open-failed',
			'witness_exists' => false,
			'stdout' => '',
			'stderr' => '',
			'running' => false,
			'exitcode' => -1,
		];
	}

	fclose($pipes[0]);
	stream_set_blocking($pipes[1], false);
	stream_set_blocking($pipes[2], false);

	$stdout = '';
	$stderr = '';
	$deadline = microtime(true) + 12.0;
	$witness = false;
	while (microtime(true) < $deadline) {
		$stdout .= (string)stream_get_contents($pipes[1]);
		$stderr .= (string)stream_get_contents($pipes[2]);
		if (is_file(WITNESS_PATH)) {
			$witness = true;
			break;
		}
		$status = proc_get_status($proc);
		if (!$status['running']) {
			break;
		}
		usleep(100000);
	}

	$stdout .= (string)stream_get_contents($pipes[1]);
	$stderr .= (string)stream_get_contents($pipes[2]);
	$status = proc_get_status($proc);
	if ($status['running']) {
		proc_terminate($proc, 15);
		usleep(250000);
		$status = proc_get_status($proc);
		if ($status['running']) {
			proc_terminate($proc, 9);
			usleep(100000);
		}
	}
	fclose($pipes[1]);
	fclose($pipes[2]);
	$exit = proc_close($proc);

	return [
		'dev' => $dev,
		'error' => '',
		'witness_exists' => is_file(WITNESS_PATH) || $witness,
		'stdout' => trim_log($stdout),
		'stderr' => trim_log($stderr),
		'running' => false,
		'exitcode' => $exit,
		'conf_path' => $path,
	];
}

function trim_log(string $blob): string
{
	$blob = trim($blob);
	if (strlen($blob) > 4000) {
		return substr($blob, 0, 2000) . "\n...\n" . substr($blob, -2000);
	}
	return $blob;
}

function oracle_status(): array
{
	$exists = is_file(WITNESS_PATH);
	return [
		'exists' => $exists,
		'path' => WITNESS_PATH,
		'body' => $exists ? witness_body() : '',
	];
}

function witness_body(): string
{
	if (!is_file(WITNESS_PATH)) {
		return '';
	}
	$body = file_get_contents(WITNESS_PATH);
	return is_string($body) ? $body : '';
}

function harness_write(): array
{
	$data = read_input();
	if (empty($data['injection_proven']) || empty($data['control_clean'])) {
		send_json(400, ['error' => 'harness-write-requires-proof']);
	}
	if (is_file(WITNESS_PATH)) {
		return oracle_status() + ['wrote' => false, 'reason' => 'already-present'];
	}
	file_put_contents(WITNESS_PATH, WITNESS_NAME . "\n");
	return oracle_status() + ['wrote' => true, 'reason' => 'harness-after-proof'];
}

function send_json(int $status, array $payload): void
{
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	exit;
}

function send_text(int $status, string $body): void
{
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit;
}
