<?php

/**
 * PHP-CLI gadget for OPNsense 26.7.6 ntpd_configure_do.
 *
 * Stubs only. Interpolation of GPS fudge1/fudge2/refid and the timeserver
 * CR/LF strip stay in the unmodified pin copy at pin/ntpd.inc.
 */

declare(strict_types=1);

const WITNESS = 'OPNSENSE-NTP-GPS-FUDGE-WITNESS';
const PIN_NTPD = __DIR__ . '/pin/ntpd.inc';
const NTP_CONF = '/var/etc/ntpd.conf';
const ORACLE_CONF = '/oracle/ntpd.conf';
const GPS_PORT = 'cua0';
const GPS_DEVICE = '/dev/cua0';

$config = [];

function gettext($message)
{
    return $message;
}

function configd_run($cmd, $detach = false)
{
    return '';
}

function killbyname($procname, $sig = 'TERM', $waitforit = true)
{
}

function service_log(string $message, bool $verbose = true): void
{
}

function shell_safe($format, $args = [], $explode = false, $separator = "\n")
{
    // Skip /etc/remote append inside ntpd_configure_gps.
    return '1';
}

function mwexecf($format, $args = [], $mute = false)
{
    file_put_contents(
        '/oracle/mwexec.txt',
        "skipped " . (is_string($format) ? $format : json_encode($format)) . "\n",
        FILE_APPEND
    );
    return 0;
}

function mwexecfb($format, $args = [], $opts = [])
{
    return mwexecf($format, $args, true);
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

function ensure_gps_char_device(string $path): void
{
    if (file_exists($path) && filetype($path) === 'char') {
        return;
    }
    if (file_exists($path)) {
        unlink($path);
    }
    $made = false;
    if (function_exists('posix_mknod') && defined('POSIX_S_IFCHR') && function_exists('posix_makedev')) {
        $made = posix_mknod($path, POSIX_S_IFCHR | 0666, posix_makedev(1, 3));
    }
    if (!$made) {
        $proc = proc_open(
            ['mknod', $path, 'c', '1', '3'],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        if (is_resource($proc)) {
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
        }
    }
    if (!file_exists($path) || filetype($path) !== 'char') {
        throw new RuntimeException("gps-char-missing path={$path}");
    }
}

function emit_result(array $payload, int $code): int
{
    echo json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n";
    return $code;
}

if (!is_file(PIN_NTPD)) {
    exit(emit_result(['ok' => false, 'error' => 'pin-ntpd-missing'], 1));
}

require PIN_NTPD;

try {
    @mkdir('/var/etc', 0755, true);
    @mkdir('/var/log/ntp', 0755, true);
    @mkdir('/var/empty', 0775, true);
    @mkdir('/oracle', 0755, true);
    @unlink('/oracle/mwexec.txt');
    ensure_gps_char_device(GPS_DEVICE);

    $config = [];
    $config['system']['timeservers'] = "0.opnsense.pool.ntp.org pool.example\nlogfile";
    $config['ntpd'] = [
        'gps' => [
            'port' => GPS_PORT,
            'fudge1' => "0.0\nlogfile /oracle/" . WITNESS,
        ],
    ];

    ntpd_configure_do(false);

    if (!is_file(NTP_CONF)) {
        throw new RuntimeException('ntpd-conf-missing');
    }

    $conf = file_get_contents(NTP_CONF);
    if ($conf === false) {
        throw new RuntimeException('ntpd-conf-unreadable');
    }
    if (file_put_contents(ORACLE_CONF, $conf) === false) {
        throw new RuntimeException('oracle-conf-write');
    }

    $lines = preg_split("/\r\n|\n|\r/", $conf) ?: [];
    exit(emit_result([
        'ok' => true,
        'conf_path' => ORACLE_CONF,
        'pin' => PIN_NTPD,
        'gps_char' => filetype(GPS_DEVICE),
        'gps_setup' => in_array('# GPS Setup', $lines, true),
        'line_count' => count($lines),
        'mwexec_skipped' => is_file('/oracle/mwexec.txt'),
    ], 0));
} catch (Throwable $exc) {
    exit(emit_result([
        'ok' => false,
        'error' => $exc->getMessage(),
    ], 1));
}
