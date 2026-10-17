<?php

/**
 * PHP CLI gadget for OPNsense 26.7.6 tunables -> /boot/loader.conf.
 *
 * Pin: tag 26.7.6 peel a842fe48c21288d11a422cb944678e8eb308becf
 * Executes pin system.inc system_login_configure() loader.conf interpolation.
 */

const PIN_TAG = '26.7.6';
const PIN_SHA = 'a842fe48c21288d11a422cb944678e8eb308becf';
const WITNESS = 'OPNSENSE-TUNABLES-LOADER-WITNESS';
const TUNABLE_NAME = 'hw.usb.no_boot_wait';
const BOOT_LOADER = '/boot/loader.conf';

if (!function_exists('gettext')) {
    function gettext($message)
    {
        return $message;
    }
}

function is_ipv6_allowed()
{
    return false;
}

function log_msg($message, $prio = 0)
{
    return true;
}

function service_log($message, $verbose = false)
{
    return true;
}

function local_sync_accounts()
{
    return true;
}

function mwexecf($cmd, $args = null)
{
    return 0;
}

function configd_run($cmd, $detach = false)
{
    return '';
}

function &config_read_array()
{
    global $config;

    $current = &$config;
    $insert_mode = true;
    $keys = func_get_args();
    if ($keys !== [] && is_bool($keys[array_key_last($keys)])) {
        $insert_mode = array_pop($keys);
    }

    foreach ($keys as $key) {
        if (!isset($current[$key]) || !is_array($current[$key])) {
            if ($insert_mode) {
                $current[$key] = [];
            } else {
                $detached = [];
                return $detached;
            }
        }
        $current = &$current[$key];
    }

    return $current;
}

function lab_value(string $case): string
{
    if ($case === 'positive') {
        return "1\"\n# " . WITNESS;
    }
    if ($case === 'negative') {
        return '1';
    }
    fwrite(STDERR, "usage: gadget.php positive|negative\n");
    exit(2);
}

$case = $argv[1] ?? '';
$value = lab_value($case);

$config = [
    'system' => [
        'usevirtualterminal' => '1',
    ],
    'sysctl' => [
        'item' => [
            [
                'tunable' => TUNABLE_NAME,
                'value' => $value,
            ],
        ],
    ],
];

require __DIR__ . '/pin/system.inc';

if (!is_dir('/boot')) {
    mkdir('/boot', 0755, true);
}
if (!is_dir('/oracle')) {
    mkdir('/oracle', 0755, true);
}

file_put_contents(BOOT_LOADER, '');
if (!is_file('/etc/ttys')) {
    file_put_contents('/etc/ttys', "ttyv0\t\"/usr/libexec/getty Pc\"\txterm\ton secure\n");
}

system_login_configure(false);

$blob = file_get_contents(BOOT_LOADER);
if ($blob === false) {
    fwrite(STDERR, "missing " . BOOT_LOADER . "\n");
    exit(1);
}

$oracle = '/oracle/loader-' . $case . '.conf';
if (file_put_contents($oracle, $blob) === false) {
    fwrite(STDERR, "write-failed " . $oracle . "\n");
    exit(1);
}

$payload = [
    'case' => $case,
    'pin_tag' => PIN_TAG,
    'pin_sha' => PIN_SHA,
    'tunable' => TUNABLE_NAME,
    'oracle' => $oracle,
    'boot' => BOOT_LOADER,
    'bytes' => strlen($blob),
];
echo json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n";
