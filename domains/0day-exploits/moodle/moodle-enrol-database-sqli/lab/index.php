<?php
/**
 * Faithful gadget of Moodle v5.2.3 enrol_database SQL builders.
 * Pin: tag v5.2.3 (344232c153). Source: public/enrol/database/lib.php.
 * External enrol DB is the sink. Moodle $DB is not queried.
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

const PIN = '5.2.3';
const PIN_SHA = '344232c15336c71b80f9aca8359ce0e0a9f3d116';
const PIN_SOURCE = 'public/enrol/database/lib.php';
const REMOTE_TABLE = 'enrolments';
const REMOTE_COURSE_FIELD = 'courseid';

/**
 * @param array<string, mixed> $payload
 */
function json_out(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    exit;
}

function request_path(): string
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    return is_string($path) && $path !== '' ? $path : '/';
}

function connect_enrol_db(): mysqli
{
    $host = getenv('ENROL_DB_HOST') ?: 'enrol-db';
    $user = getenv('ENROL_DB_USER') ?: 'enrolu';
    $pass = getenv('ENROL_DB_PASS') ?: 'enrolpass';
    $name = getenv('ENROL_DB_NAME') ?: 'enrol_ext';
    $last = 'db-connect-failed';
    mysqli_report(MYSQLI_REPORT_OFF);
    for ($i = 0; $i < 30; $i++) {
        $db = @new mysqli($host, $user, $pass, $name, 3306);
        if (!$db->connect_errno) {
            $db->set_charset('utf8mb4');
            return $db;
        }
        $last = $db->connect_error ?: 'db-connect-failed';
        usleep(200000);
    }
    json_out(['ok' => false, 'error' => 'db-connect-failed', 'detail' => $last], 503);
}

/**
 * Copied from enrol_database_plugin in public/enrol/database/lib.php
 * (v5.2.3 344232c153) lines 918-936, 971-994. get_config is a stand-in
 * for enrol_plugin::get_config. Methods are public so the gadget can call them.
 */
class enrol_database_gadget
{
    /** @var array<string, mixed> */
    private array $config;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * @param string $name
     * @return mixed
     */
    public function get_config($name)
    {
        return $this->config[$name] ?? null;
    }

    /**
     * @param string $table
     * @param array<string, mixed> $conditions
     * @param array<int, string> $fields
     * @param bool $distinct
     * @param string $sort
     * @return string
     */
    public function db_get_sql($table, array $conditions, array $fields, $distinct = false, $sort = "")
    {
        $fields = $fields ? implode(',', $fields) : "*";
        $where = array();
        if ($conditions) {
            foreach ($conditions as $key=>$value) {
                $value = $this->db_encode($this->db_addslashes($value));

                $where[] = "$key = '$value'";
            }
        }
        $where = $where ? "WHERE ".implode(" AND ", $where) : "";
        $sort = $sort ? "ORDER BY $sort" : "";
        $distinct = $distinct ? "DISTINCT" : "";
        $sql = "SELECT $distinct $fields
                  FROM $table
                 $where
                  $sort";

        return $sql;
    }

    /**
     * @param string $text
     * @return string
     */
    public function db_addslashes($text)
    {
        // Use custom made function for now - it is better to not rely on adodb or php defaults.
        if ($this->get_config('dbsybasequoting')) {
            $text = str_replace('\\', '\\\\', $text);
            $text = str_replace(array('\'', '"', "\0"), array('\\\'', '\\"', '\\0'), $text);
        } else {
            $text = str_replace("'", "''", $text);
        }
        return $text;
    }

    /**
     * @param mixed $text
     * @return mixed
     */
    public function db_encode($text)
    {
        $dbenc = $this->get_config('dbencoding');
        if (empty($dbenc) or $dbenc == 'utf-8') {
            return $text;
        }
        if (is_array($text)) {
            foreach($text as $k=>$value) {
                $text[$k] = $this->db_encode($value);
            }
            return $text;
        } else {
            return $text;
        }
    }
}

function gadget_config(): enrol_database_gadget
{
    // Defaults from public/enrol/database/settings.php: dbsybasequoting=0, dbencoding=utf-8.
    return new enrol_database_gadget([
        'dbtype' => 'mysqli',
        'dbsybasequoting' => 0,
        'dbencoding' => 'utf-8',
        'remoteenroltable' => REMOTE_TABLE,
        'remotecoursefield' => REMOTE_COURSE_FIELD,
        'remoteuserfield' => 'userid',
        'localcoursefield' => 'idnumber',
    ]);
}

/**
 * @return list<string>
 */
function fetch_userids(mysqli $db, string $sql): array
{
    $result = $db->query($sql);
    if ($result === false) {
        json_out([
            'ok' => false,
            'error' => 'enrol-db-query-failed',
            'sql' => $sql,
            'detail' => $db->error,
        ], 500);
    }
    $userids = [];
    while ($row = $result->fetch_assoc()) {
        $userids[] = (string) ($row['userid'] ?? '');
    }
    $result->free();
    return $userids;
}

/**
 * @param list<string> $userids
 * @return array<string, mixed>
 */
function sync_payload(
    string $plugin,
    string $style,
    string $idnumber,
    string $sql,
    bool $executed,
    array $userids,
    string $skipped = '',
): array
{
    $witness = getenv('WITNESS') ?: 'MOODLE-ENROL-DATABASE-SQLI-WITNESS';
    return [
        'ok' => true,
        'how' => 'gadget',
        'pin' => PIN,
        'sha' => PIN_SHA,
        'source' => PIN_SOURCE,
        'sink' => 'enrol-db',
        'plugin' => $plugin,
        'style' => $style,
        'idnumber' => $idnumber,
        'sql' => $sql,
        'executed' => $executed,
        'placeholder' => str_contains($sql, '?'),
        'row_count' => count($userids),
        'userids' => $userids,
        'has_witness' => in_array($witness, $userids, true),
        'skipped' => $skipped,
    ];
}

$path = request_path();
$mode = isset($_GET['mode']) ? (string) $_GET['mode'] : ($path === '/health' ? 'ping' : 'ping');
$plugin = isset($_GET['plugin']) ? (string) $_GET['plugin'] : 'on';
$style = isset($_GET['style']) ? (string) $_GET['style'] : 'concat';
$idnumber = isset($_GET['idnumber']) ? (string) $_GET['idnumber'] : '';

if ($mode === 'ping' || $mode === 'health') {
    $db = connect_enrol_db();
    $ping = $db->query('SELECT 1');
    json_out([
        'ok' => $ping !== false,
        'mode' => 'ping',
        'how' => 'gadget',
        'pin' => PIN,
        'sha' => PIN_SHA,
        'source' => PIN_SOURCE,
        'sink' => 'enrol-db',
        'db' => $ping !== false ? 'ok' : 'fail',
        'package' => 'moodle/enrol_database',
    ]);
}

if ($mode !== 'sync') {
    json_out(['ok' => false, 'error' => 'unknown-mode', 'mode' => $mode], 400);
}

if ($plugin !== 'on') {
    json_out(sync_payload(
        'off',
        $style,
        $idnumber,
        '',
        false,
        [],
        'plugin-disabled',
    ));
}

$db = connect_enrol_db();
$gadget = gadget_config();

if ($style === 'param') {
    // auth_db leftover of MSA-26-0005 / MDL-88138: parameterized Execute($sql, [$value]).
    $sql = "SELECT userid, role
                  FROM " . REMOTE_TABLE . "
                 WHERE " . REMOTE_COURSE_FIELD . " = ?";
    $stmt = $db->prepare($sql);
    if ($stmt === false) {
        json_out(['ok' => false, 'error' => 'param-prepare-failed', 'detail' => $db->error], 500);
    }
    $stmt->bind_param('s', $idnumber);
    if (!$stmt->execute()) {
        json_out(['ok' => false, 'error' => 'param-execute-failed', 'detail' => $stmt->error], 500);
    }
    $result = $stmt->get_result();
    $userids = [];
    if ($result !== false) {
        while ($row = $result->fetch_assoc()) {
            $userids[] = (string) ($row['userid'] ?? '');
        }
        $result->free();
    }
    $stmt->close();
    json_out(sync_payload('on', 'param', $idnumber, $sql, true, $userids));
}

// Cron sync_enrolments interpolates course->mapping (default local field: idnumber).
$sql = $gadget->db_get_sql(
    REMOTE_TABLE,
    array(REMOTE_COURSE_FIELD => $idnumber),
    array('userid', 'role'),
);
$userids = fetch_userids($db, $sql);
json_out(sync_payload('on', 'concat', $idnumber, $sql, true, $userids));
