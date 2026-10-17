<?php

declare(strict_types=1);

require __DIR__ . '/sanitize.php';

const WITNESS = 'OPNSENSE-FIRMWARE-MIRROR-SED-WITNESS';
const SAMPLE = '/lab/templates/OPNsense.conf.sample';
const APPLY = '/lab/apply_mirror.sh';
const ORACLE = '/oracle/secret';
const PIN_TAG = '26.7.6';
const PIN_SHA = 'a842fe48c21288d11a422cb944678e8eb308becf';

/**
 * @param array<string, mixed> $payload
 */
function json_out(int $status, array $payload): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function request_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url($uri, PHP_URL_PATH);
    return is_string($path) && $path !== '' ? $path : '/';
}

function read_json_body(): array
{
    $raw = file_get_contents('php://input');
    if (!is_string($raw) || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function field(string $conf, string $key): string
{
    if (!preg_match('/^[[:space:]]*' . preg_quote($key, '/') . ':[[:space:]]*"(.*)"/m', $conf, $match)) {
        return '';
    }
    return $match[1];
}

function apply_mirror(string $origin, string $mirror): array
{
    $proc = proc_open(
        ['/bin/sh', APPLY, $origin, $mirror],
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes
    );
    if (!is_resource($proc)) {
        return ['ok' => false, 'stdout' => '', 'stderr' => 'proc_open-failed', 'code' => -1];
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return [
        'ok' => $code === 0,
        'stdout' => is_string($stdout) ? $stdout : '',
        'stderr' => is_string($stderr) ? $stderr : '',
        'code' => $code,
    ];
}

$path = request_path();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($path === '/ping' && $method === 'GET') {
    json_out(200, [
        'pong' => 'pong',
        'php' => PHP_VERSION,
        'pin' => PIN_TAG,
        'sha' => PIN_SHA,
        'filter' => 'FILTER_SANITIZE_URL',
        'sed' => 'gnu-i-no-darwin-suffix',
    ]);
    return true;
}

if ($path === '/case' && $method === 'POST') {
    $body = read_json_body();
    $name = isset($body['name']) && is_string($body['name']) ? $body['name'] : '';
    $mirror = isset($body['mirror']) && is_string($body['mirror']) ? $body['mirror'] : '';
    if (!preg_match('/^[a-z0-9_-]+$/', $name) || $mirror === '') {
        json_out(400, ['error' => 'bad-case']);
        return true;
    }

    $values = [
        'mirror' => $mirror,
        'plugins' => 'os-example',
    ];
    $sanitized_values = firmware_set_sanitize($values);
    $sanitized = $sanitized_values['mirror'] ?? '';
    if (!is_string($sanitized)) {
        $sanitized = '';
    }

    $work_dir = '/work/' . $name;
    if (!is_dir($work_dir) && !mkdir($work_dir, 0755, true) && !is_dir($work_dir)) {
        json_out(500, ['error' => 'mkdir-failed']);
        return true;
    }
    $origin = $work_dir . '/OPNsense.conf';
    if (!copy(SAMPLE, $origin)) {
        json_out(500, ['error' => 'copy-sample-failed']);
        return true;
    }

    $applied = apply_mirror($origin, $sanitized);
    $conf = is_file($origin) ? (string) file_get_contents($origin) : '';
    $signature_type = field($conf, 'signature_type');
    $url = field($conf, 'url');
    $witness_written = false;
    if ($signature_type === 'none') {
        if (!is_dir('/oracle') && !mkdir('/oracle', 0755, true) && !is_dir('/oracle')) {
            json_out(500, ['error' => 'oracle-mkdir-failed']);
            return true;
        }
        if (file_put_contents(ORACLE, WITNESS . "\n") === false) {
            json_out(500, ['error' => 'oracle-write-failed']);
            return true;
        }
        $witness_written = true;
    }

    json_out(200, [
        'name' => $name,
        'pin' => PIN_TAG,
        'sha' => PIN_SHA,
        'raw_mirror' => $mirror,
        'sanitized' => $sanitized,
        'keeps_pipe' => str_contains($sanitized, '|'),
        'keeps_hash' => str_contains($sanitized, '#'),
        'keeps_quote' => str_contains($sanitized, '"'),
        'plugins_discarded' => !array_key_exists('plugins', $sanitized_values),
        'sed_ok' => $applied['ok'],
        'sed_code' => $applied['code'],
        'sed_stderr' => $applied['stderr'],
        'signature_type' => $signature_type,
        'url' => $url,
        'conf' => $conf,
        'witness_written' => $witness_written,
    ]);
    return true;
}

json_out(404, ['error' => 'not-found']);
return true;
