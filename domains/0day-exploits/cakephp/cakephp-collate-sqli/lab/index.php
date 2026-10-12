<?php
/**
 * Tiny CakePHP 5.4.2 app: query-string collation into StringExpression.
 */
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Cake\Database\Connection;
use Cake\Database\Driver\Postgres;
use Cake\Database\Expression\IdentifierExpression;
use Cake\Database\Expression\StringExpression;
use Cake\Database\ValueBinder;
use Composer\InstalledVersions;
use PDO;
use Throwable;

const WITNESS_DEFAULT = 'CAKEPHP-COLLATE-SQLI-WITNESS';

header('Content-Type: application/json; charset=utf-8');

/**
 * @param array<string, mixed> $payload
 */
function json_out(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function request_path(): string
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    return is_string($path) && $path !== '' ? $path : '/';
}

function pin_version(): string
{
    if (class_exists(InstalledVersions::class)) {
        foreach (['cakephp/database', 'cakephp/cakephp'] as $package) {
            if (InstalledVersions::isInstalled($package)) {
                $pretty = InstalledVersions::getPrettyVersion($package);
                if (is_string($pretty) && $pretty !== '') {
                    return $pretty;
                }
            }
        }
    }
    return 'unknown';
}

function connect_db(): Connection
{
    $host = getenv('DB_HOST') ?: 'db';
    $user = getenv('DB_USER') ?: 'lab';
    $pass = getenv('DB_PASS') ?: 'labpass';
    $name = getenv('DB_NAME') ?: 'lab';
    $last = 'db-connect-failed';
    for ($i = 0; $i < 30; $i++) {
        try {
            $driver = new Postgres([
                'host' => $host,
                'port' => 5432,
                'username' => $user,
                'password' => $pass,
                'database' => $name,
                'encoding' => 'utf8',
                'persistent' => false,
            ]);
            $conn = new Connection(['driver' => $driver]);
            $conn->execute('SELECT 1');
            return $conn;
        } catch (Throwable $exc) {
            $last = $exc->getMessage();
            usleep(200000);
        }
    }
    json_out(['ok' => false, 'error' => 'db-connect-failed', 'detail' => $last], 503);
}

function seed_secret(Connection $conn, string $witness): void
{
    $conn->execute(
        'CREATE TABLE IF NOT EXISTS lab_secret (id INTEGER PRIMARY KEY, note TEXT NOT NULL)',
    );
    $conn->execute('DELETE FROM lab_secret');
    $conn->execute(
        'INSERT INTO lab_secret (id, note) VALUES (1, :n)',
        ['n' => $witness],
    );
}

$path = request_path();
$witness = getenv('WITNESS') ?: WITNESS_DEFAULT;
$version = pin_version();

if ($path === '/health') {
    $dbOk = false;
    try {
        connect_db();
        $dbOk = true;
    } catch (Throwable $exc) {
        json_out([
            'ok' => false,
            'version' => $version,
            'db' => false,
            'error' => $exc->getMessage(),
        ], 503);
    }
    json_out(['ok' => true, 'version' => $version, 'db' => $dbOk]);
}

$collation = isset($_GET['collation']) ? (string) $_GET['collation'] : 'C';

try {
    $conn = connect_db();
    seed_secret($conn, $witness);

    $rawBinder = new ValueBinder();
    $rawSql = (new StringExpression('x', $collation))->sql($rawBinder);
    $rawBindings = [];
    foreach ($rawBinder->bindings() as $key => $binding) {
        $rawBindings[$key] = [
            'value' => $binding['value'] ?? null,
            'type' => $binding['type'] ?? null,
        ];
    }

    $idBinder = new ValueBinder();
    $idRawSql = (new IdentifierExpression('note', $collation))->sql($idBinder);

    $quoted = $conn->getDriver()->quoteIdentifier($collation);
    $simpleOk = (bool) preg_match('/^[a-zA-Z0-9]+$/', $collation);

    $query = $conn->selectQuery();
    $query->select([
        'v' => $query->func()->cast(new StringExpression('x', $collation), 'text'),
    ]);
    $compiled = $query->sql();

    $result = null;
    $execError = null;
    try {
        $row = $query->execute()->fetch(PDO::FETCH_NUM);
        if (is_array($row) && array_key_exists(0, $row)) {
            $result = $row[0];
        }
    } catch (Throwable $exc) {
        $execError = $exc->getMessage();
    }

    json_out([
        'ok' => true,
        'version' => $version,
        'collation' => $collation,
        'raw_sql' => $rawSql,
        'id_raw_sql' => $idRawSql,
        'compiled_sql' => $compiled,
        'quote_identifier' => $quoted,
        'bindings' => $rawBindings,
        'ensure_simple_ok' => $simpleOk,
        'result' => $result,
        'exec_error' => $execError,
    ]);
} catch (Throwable $exc) {
    json_out([
        'ok' => false,
        'version' => $version,
        'error' => $exc->getMessage(),
    ], 500);
}
