<?php
declare(strict_types=1);

/**
 * pfSense CE 2.9.0-DEVELOPMENT pin 9363ac5b8651a1c7a333180425ce7719070f95f9
 * leftover G3: CARP VHID stored raw, stacked IP Alias mwexec unescaped.
 */

const WITNESS = 'PFSENSE-CARP-VHID-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-CARP-VHID-WITNESS';
const STORE_PATH = '/tmp/lab-vips.json';
const CARP_UNIQID = 'labcarp1';
const ALIAS_UNIQID = 'labalias1';

ini_set('display_errors', '0');
error_reporting(E_ALL);

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
            'pin' => '9363ac5b8651a1c7a333180425ce7719070f95f9',
            'path' => getenv('PATH'),
        ]);
    }

    if ($path === '/oracle') {
        send_json(200, oracle_state());
    }

    if ($path === '/reset') {
        reset_oracle();
        send_json(200, oracle_state() + ['reset' => true]);
    }

    if ($path === '/source') {
        send_text(200, (string)file_get_contents(__FILE__));
    }

    if ($path === '/run') {
        $post = read_post();
        $sink = (string)($post['sink'] ?? '');
        $vhid = (string)($post['vhid'] ?? '');
        if ($sink === '' || $vhid === '') {
            send_json(400, ['error' => 'missing-sink-or-vhid']);
        }
        send_json(200, run_sink($sink, $vhid));
    }

    send_json(404, ['error' => 'not-found', 'path' => $path]);
}

function read_post(): array
{
    $raw = (string)file_get_contents('php://input');
    if ($raw !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            return $decoded;
        }
    }
    return $_POST;
}

function send_json(int $status, array $payload): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit(0);
}

function send_text(int $status, string $body): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $body;
    exit(0);
}

function oracle_state(): array
{
    $present = is_file(WITNESS_PATH);
    $body = $present ? (string)file_get_contents(WITNESS_PATH) : '';
    return [
        'present' => $present,
        'body' => $body,
        'path' => WITNESS_PATH,
    ];
}

function reset_oracle(): void
{
    if (is_file(WITNESS_PATH)) {
        unlink(WITNESS_PATH);
    }
}

function load_store(): array
{
    if (!is_file(STORE_PATH)) {
        return [];
    }
    $decoded = json_decode((string)file_get_contents(STORE_PATH), true);
    return is_array($decoded) ? $decoded : [];
}

function persist_vip(array $vipent): void
{
    $data = load_store();
    $key = '_vip' . $vipent['uniqid'];
    $data[$key] = $vipent;
    $data[$vipent['uniqid']] = $vipent;
    file_put_contents(STORE_PATH, json_encode($data));
}

/* saveVIP leftover: VHID stored from POST with no 1-255 check.
 * Product: firewall_virtual_ip.inc:199-202. Form_Select 1-255 is HTML only. */
function saveVIP_store(array $post): array
{
    $vipent = array();

    $vipent['mode'] = $post['mode'];
    $vipent['interface'] = $post['interface'];

    /* CARP specific fields */
    if ($post['mode'] === "carp") {
        $vipent['vhid'] = $post['vhid'];
        $vipent['advskew'] = $post['advskew'];
        $vipent['advbase'] = $post['advbase'];
        $vipent['password'] = $post['password'];
    }

    if ($post['mode'] === "carp" || $post['mode'] === "ipalias") {
        $vipent['uniqid'] = $post['uniqid'];
    }

    $vipent['subnet'] = $post['subnet'];
    $vipent['subnet_bits'] = $post['subnet_bits'];

    persist_vip($vipent);
    return $vipent;
}

function get_configured_vip($id)
{
    $data = load_store();
    return $data[$id] ?? null;
}

function get_configured_vip_interface($carpid)
{
    $vip = get_configured_vip($carpid);
    if ($vip === null) {
        return null;
    }
    return $vip['interface'];
}

function get_real_interface($iface)
{
    return 'lo0';
}

function does_interface_exist($realif): bool
{
    return true;
}

function g_get($key)
{
    return false;
}

function config_path_enabled($path, $key = null): bool
{
    return false;
}

function is_ipaddrv4($ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

function is_ipaddrv6($ip): bool
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
}

function convert_real_interface_to_friendly_interface_name($realif)
{
    return 'lan';
}

function is_pseudo_interface($realif): bool
{
    return false;
}

function get_interface_gateway($if)
{
    return '';
}

function get_interface_gateway_v6($if)
{
    return '';
}

function gettext($s)
{
    return $s;
}

function file_notice($id, $msg, $cat, $url): void
{
}

/* util.inc mwexec foreground path: PHP exec of one string. */
function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false)
{
    $retval = 0;
    $outputarray = array();
    exec("$command 2>&1", $outputarray, $retval);
    $GLOBALS['LAST_EXEC'] = [
        'command' => $command,
        'output' => implode("\n", $outputarray),
        'retval' => $retval,
        'via' => 'mwexec',
    ];
    return $retval;
}

/* Product interfaces.inc:3207-3239. Do not escapeshellarg leftover VHID. */
function interface_ipalias_configure(&$vip)
{
    $gateway = '';
    if ($vip['mode'] != 'ipalias') {
        return;
    }

    $realif = get_real_interface("_vip{$vip['uniqid']}");
    if ($realif != "lo0") {
        $if = convert_real_interface_to_friendly_interface_name($realif);
        if (empty($if) || !config_path_enabled("interfaces/{$if}")) {
            return;
        }
        if (is_pseudo_interface($realif)) {
            if (is_ipaddrv4($vip['subnet'])) {
                $gateway = get_interface_gateway($if);
            } else if (!config_path_enabled('system', 'use_if_pppoe')) {
                $gateway = get_interface_gateway_v6($if);
            }
        }
    }

    $af = 'inet';
    if (is_ipaddrv6($vip['subnet'])) {
        $af = 'inet6';
    }
    $iface = $vip['interface'];
    $vhid = '';
    if (substr($vip['interface'], 0, 4) == "_vip") {
        $carpvip = get_configured_vip($vip['interface']);
        $iface = $carpvip['interface'];
        $vhid = "vhid {$carpvip['vhid']}";
    }
    mwexec("/sbin/ifconfig " . escapeshellarg($realif) ." {$af} ". escapeshellarg($vip['subnet']) ."/" . escapeshellarg($vip['subnet_bits']) . " alias {$gateway} {$vhid}");
    unset($iface, $af, $realif, $carpvip, $vhid, $gateway);
}

/* Product interfaces.inc:3242-3284. CONTROL: VHID is escapeshellarg'd. */
function interface_carp_configure(&$vip, $maintenancemode_only = false, $ipalias_reload = false)
{
    if ($vip['mode'] != "carp") {
        return;
    }

    $realif = get_real_interface($vip['interface']);
    if (!does_interface_exist($realif)) {
        return;
    }
    if ($realif != "lo0") {
        if (!config_path_enabled("interfaces/{$vip['interface']}")) {
            return;
        }
    }

    $password = '';
    $vip_password = $vip['password'];
    $vip_password = escapeshellarg(addslashes(str_replace(" ", "",
        $vip_password)));
    if ($vip['password'] != "") {
        $password = " pass {$vip_password}";
    }

    $advbase = "";
    if (!empty($vip['advbase'])) {
        $advbase = "advbase " . escapeshellarg($vip['advbase']);
    }

    if (config_path_enabled('','virtualip_carp_maintenancemode')) {
        $advskew = "advskew 254";
    } else {
        $advskew = "advskew " . escapeshellarg($vip['advskew']);
    }

    mwexec("/sbin/ifconfig {$realif} vhid " . escapeshellarg($vip['vhid']) .
        " {$advskew} {$advbase} {$password}");

    if (!$maintenancemode_only) {
        if (is_ipaddrv4($vip['subnet'])) {
            mwexec("/sbin/ifconfig {$realif} " .
                escapeshellarg($vip['subnet']) . "/" .
                escapeshellarg($vip['subnet_bits']) .
                " alias vhid " . escapeshellarg($vip['vhid']));
        } elseif (is_ipaddrv6($vip['subnet'])) {
            mwexec("/sbin/ifconfig {$realif} inet6 " .
                escapeshellarg($vip['subnet']) . " prefixlen " .
                escapeshellarg($vip['subnet_bits']) .
                " alias vhid " . escapeshellarg($vip['vhid']));
        }
    }
}

/* Product pfsense-utils.inc:780-794. VHID inside double quotes. */
function get_carp_interface_status($carpid)
{
    $carpiface = get_configured_vip_interface($carpid);
    if ($carpiface == NULL)
        return "";
    $interface = get_real_interface($carpiface);
    if ($interface == NULL)
        return "";
    $vip = get_configured_vip($carpid);
    if ($vip == NULL || !isset($vip['vhid']))
        return "";

    $vhid = $vip['vhid'];
    $carp_query = [];
    exec("/sbin/ifconfig {$interface} | /usr/bin/grep \"carp:.* vhid {$vhid} \"", $carp_query);
    $GLOBALS['LAST_EXEC'] = [
        'command' => "/sbin/ifconfig {$interface} | /usr/bin/grep \"carp:.* vhid {$vhid} \"",
        'output' => implode("\n", $carp_query),
        'retval' => 0,
        'via' => 'exec',
    ];
    foreach ($carp_query as $int) {
        if (stripos($int, "MASTER"))
            return "MASTER";
        elseif (stripos($int, "BACKUP"))
            return "BACKUP";
        elseif (stripos($int, "INIT"))
            return "INIT";
    }

    return "";
}

function run_sink(string $sink, string $vhid): array
{
    $GLOBALS['LAST_EXEC'] = [
        'command' => '',
        'output' => '',
        'retval' => null,
        'via' => '',
    ];

    $carp_post = [
        'mode' => 'carp',
        'interface' => 'lan',
        'vhid' => $vhid,
        'advskew' => '0',
        'advbase' => '1',
        'password' => 'labpass',
        'uniqid' => CARP_UNIQID,
        'subnet' => '192.0.2.1',
        'subnet_bits' => '32',
    ];
    $carp = saveVIP_store($carp_post);

    $alias = null;
    $status = '';

    if ($sink === 'carp') {
        interface_carp_configure($carp);
    } elseif ($sink === 'ipalias') {
        $alias_post = [
            'mode' => 'ipalias',
            'interface' => '_vip' . CARP_UNIQID,
            'uniqid' => ALIAS_UNIQID,
            'subnet' => '192.0.2.10',
            'subnet_bits' => '32',
            'vhid' => '',
            'advskew' => '',
            'advbase' => '',
            'password' => '',
        ];
        $alias = saveVIP_store($alias_post);
        interface_ipalias_configure($alias);
    } elseif ($sink === 'status') {
        $status = get_carp_interface_status('_vip' . CARP_UNIQID);
    } else {
        send_json(400, ['error' => 'unknown-sink', 'sink' => $sink]);
    }

    $exec = $GLOBALS['LAST_EXEC'];
    return [
        'sink' => $sink,
        'stored_vhid' => $carp['vhid'],
        'command' => $exec['command'],
        'output' => $exec['output'],
        'retval' => $exec['retval'],
        'via' => $exec['via'],
        'status' => $status,
        'oracle' => oracle_state(),
        'escaped_vhid' => escapeshellarg($vhid),
    ];
}
