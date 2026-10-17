<?php

/**
 * PHP CLI gadget: load pin interfaces.inc and call interfaces_wlan_configure.
 * Interpolation lines stay byte-identical in pin/interfaces.inc. No wpa_supplicant.
 */

const LAB_LABEL = 'opnsense-wlan-wpa-line';
const LAB_WITNESS = 'OPNSENSE-WLAN-WPA-LINE-WITNESS';
const LAB_PIN_TAG = '26.7.6';
const LAB_PIN_SHA = 'a842fe48c21288d11a422cb944678e8eb308becf';
const LAB_DEVICE = 'ath0_wlan0';
const LAB_SSID = 'lab-ssid';
const LAB_IDENTITY_NEG = 'user';
const LAB_IDENTITY_POS = "user\n# OPNSENSE-WLAN-WPA-LINE-WITNESS";
const LAB_CONF_NAME = 'wpa_supplicant_ath0_wlan0.conf';

require_once __DIR__ . '/stubs/helpers.php';
require_once __DIR__ . '/stubs/Wlan.php';

set_include_path(__DIR__ . '/stubs' . PATH_SEPARATOR . get_include_path());
require_once __DIR__ . '/pin/interfaces.inc';

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($uri) || $uri === '') {
    $uri = '/';
}

try {
    route($uri);
} catch (Throwable $exc) {
    send_json(500, [
        'error' => $exc->getMessage(),
        'file' => basename($exc->getFile()),
        'line' => $exc->getLine(),
    ]);
}

function route(string $path): void
{
    if ($path === '/ping') {
        send_json(200, [
            'ok' => true,
            'pong' => 'pong',
            'label' => LAB_LABEL,
            'version' => LAB_PIN_TAG,
            'sha' => LAB_PIN_SHA,
            'function' => 'interfaces_wlan_configure',
        ]);
    }

    if ($path === '/pin/PIN.txt') {
        send_text(200, pin_file('PIN.txt'));
    }
    if ($path === '/pin/interfaces.inc') {
        send_text(200, pin_file('interfaces.inc'));
    }
    if ($path === '/pin/Wlan.xml') {
        send_text(200, pin_file('Wlan.xml'));
    }
    if ($path === '/pin/TextField.php') {
        send_text(200, pin_file('TextField.php'));
    }

    if ($path === '/oracle/wpa_supplicant.conf' || $path === '/oracle/secret') {
        $full = $path;
        if (!is_file($full)) {
            send_json(404, ['error' => 'oracle-missing', 'path' => $path]);
        }
        send_text(200, (string)file_get_contents($full));
    }

    if ($path === '/run') {
        $case = $_GET['case'] ?? '';
        if (!is_string($case) || ($case !== 'positive' && $case !== 'negative')) {
            send_json(400, ['error' => 'case-must-be-positive-or-negative']);
        }
        send_json(200, run_case($case));
    }

    send_json(404, ['error' => 'not-found', 'path' => $path]);
}

function pin_file(string $name): string
{
    $full = __DIR__ . '/pin/' . $name;
    if (!is_file($full)) {
        throw new RuntimeException('pin-file-missing ' . $name);
    }
    $body = file_get_contents($full);
    if ($body === false) {
        throw new RuntimeException('pin-file-unreadable ' . $name);
    }
    return $body;
}

/**
 * @return array<string, mixed>
 */
function run_case(string $case): array
{
    $identity = $case === 'positive' ? LAB_IDENTITY_POS : LAB_IDENTITY_NEG;

    @mkdir('/var/etc', 0755, true);
    @mkdir('/oracle', 0755, true);
    @mkdir('/tmp', 0755, true);

    $written = '/var/etc/' . LAB_CONF_NAME;
    @unlink($written);
    @unlink('/tmp/' . LAB_DEVICE . '_setup.sh');

    \OPNsense\Interfaces\Wlan::$lab_config = wlan_config($identity);
    interfaces_wlan_configure(LAB_DEVICE, false);

    if (!is_file($written)) {
        throw new RuntimeException('wpa-conf-not-written');
    }
    $conf = (string)file_get_contents($written);
    if ($conf === '') {
        throw new RuntimeException('wpa-conf-empty');
    }

    if (file_put_contents('/oracle/wpa_supplicant.conf', $conf) === false) {
        throw new RuntimeException('oracle-conf-write-failed');
    }

    $lines = preg_split("/\r\n|\n|\r/", $conf) ?: [];
    $identity_lines = [];
    $ssid_lines = [];
    $witness_lines = [];
    foreach ($lines as $line) {
        $stripped = ltrim($line);
        if (str_starts_with($stripped, 'identity=')) {
            $identity_lines[] = $line;
        }
        if (str_starts_with($stripped, 'ssid=')) {
            $ssid_lines[] = $line;
        }
        if (str_contains($line, LAB_WITNESS)) {
            $witness_lines[] = $line;
        }
    }

    $identity_newline = false;
    foreach ($identity_lines as $line) {
        if (substr_count($line, '"') < 2) {
            $identity_newline = true;
        }
    }
    $extra_directive = false;
    foreach ($witness_lines as $line) {
        if (!str_starts_with(ltrim($line), 'identity=')) {
            $extra_directive = true;
        }
    }
    $ssid_single = count($ssid_lines) === 1
        && str_contains($ssid_lines[0], '"' . LAB_SSID . '"')
        && !str_contains($ssid_lines[0], "\n")
        && !str_contains($ssid_lines[0], LAB_WITNESS);

    $secret = implode("\n", [
        LAB_WITNESS,
        'case=' . $case,
        'identity-newline=' . ($identity_newline ? 'yes' : 'no'),
        'extra-directive=' . ($extra_directive ? 'yes' : 'no'),
        'ssid-control=' . ($ssid_single ? 'single-line' : 'broken'),
        'identity-lines=' . (string)count($identity_lines),
        'ssid-lines=' . (string)count($ssid_lines),
        'witness-lines=' . (string)count($witness_lines),
        '',
    ]);
    if (file_put_contents('/oracle/secret', $secret) === false) {
        throw new RuntimeException('oracle-secret-write-failed');
    }

    return [
        'ok' => true,
        'case' => $case,
        'version' => LAB_PIN_TAG,
        'sha' => LAB_PIN_SHA,
        'device' => LAB_DEVICE,
        'identity_raw' => $identity,
        'conf' => $conf,
        'identity_lines' => $identity_lines,
        'ssid_lines' => $ssid_lines,
        'witness_lines' => $witness_lines,
        'identity_newline' => $identity_newline,
        'extra_directive' => $extra_directive,
        'ssid_single' => $ssid_single,
        'wpa_supplicant_started' => false,
    ];
}

/**
 * @return array<string, mixed>
 */
function wlan_config(string $identity): array
{
    return [
        'standard' => '11ng',
        'ssid' => LAB_SSID,
        'protmode' => '',
        'channel' => '',
        'diversity' => '',
        'txantenna' => '',
        'rxantenna' => '',
        'mode' => 'bss',
        'hidessid' => '',
        'pureg' => '',
        'puren' => '',
        'apbridge' => '',
        'turbo' => '',
        'wme' => '',
        'wep' => [
            'enable' => '',
            'keys' => '',
        ],
        'wpa' => [
            'auth_algs' => '1',
            'enable' => '1',
            'wpa_key_mgmt' => 'WPA-EAP',
            'wpa_eap_method' => 'PEAP',
            'passphrase' => 'lab-pass',
            'wpa_eap_p2_auth' => 'MSCHAPv2',
            'identity' => $identity,
            'wpa_eap_cacertref' => '',
            'wpa_eap_cltcertref' => '',
            'wpa_pairwise' => 'CCMP',
        ],
        'regcountry' => '',
        'regdomain' => '',
        'reglocation' => '',
        'txpower' => '',
    ];
}

/**
 * @param array<string, mixed> $payload
 */
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
