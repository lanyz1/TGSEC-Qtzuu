<?php
/**
 * Tiny CakePHP Database app for leftover #4.
 * Forwards query-string start into AggregateExpression::range().
 */
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Cake\Database\Connection;
use Cake\Database\Driver\Sqlite;
use Composer\InstalledVersions;

header('Content-Type: application/json; charset=utf-8');

$package = 'cakephp/database';
$version = InstalledVersions::isInstalled($package)
    ? (string) InstalledVersions::getPrettyVersion($package)
    : 'unknown';
$reference = InstalledVersions::isInstalled($package)
    ? (string) InstalledVersions::getReference($package)
    : '';

/**
 * @param array<string, mixed> $payload
 */
function reply(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    exit;
}

$mode = isset($_GET['mode']) ? (string) $_GET['mode'] : 'ping';

$base = [
    'ok' => true,
    'mode' => $mode,
    'package' => $package,
    'version' => $version,
    'reference' => $reference,
    'pin' => 'cakephp/cakephp 5.4.2 887b641de9f7aba06071f98f17edcbc573cbcf63',
];

if ($mode === 'ping') {
    reply($base);
}

try {
    $driver = new Sqlite(['database' => ':memory:']);
    $conn = new Connection(['driver' => $driver]);
    $q = $conn->selectQuery();

    if ($mode === 'rows') {
        $n = (int) ($_GET['n'] ?? 3);
        $expr = $q->func()->count('*')->over()->rows($n);
    } elseif ($mode === 'range') {
        // App forwards request data into range(); start is a string, not int.
        $start = (string) ($_GET['start'] ?? '1');
        $end = array_key_exists('end', $_GET) ? (string) $_GET['end'] : 0;
        $expr = $q->func()->count('*')->over()->range($start, $end);
    } else {
        reply([...$base, 'ok' => false, 'error' => 'unknown-mode'], 400);
    }

    $q = $q->select(['n' => $expr])->from('sqlite_master');
    $sql = $q->sql();
    $bindings = [];
    foreach ($q->getValueBinder()->bindings() as $name => $bound) {
        $bindings[$name] = $bound['value'] ?? null;
    }

    reply([...$base, 'sql' => $sql, 'bindings' => $bindings]);
} catch (Throwable $e) {
    reply([...$base, 'ok' => false, 'error' => $e->getMessage()], 500);
}
