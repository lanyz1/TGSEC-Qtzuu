<?php

/**
 * Moodle v5.2.3 Blackboard img src file-read gadget.
 *
 * Copies qformat_blackboard_six_base::text_field / store_file_for_text_field
 * from public/question/format/blackboard_six/formatbase.php (tag v5.2.3).
 * Teacher zip import only. Not a live Moodle site.
 */

declare(strict_types=1);

const WITNESS = "MOODLE-BLACKBOARD-IMG-WITNESS";
const PIN_TAG = "v5.2.3";
const PIN_SHA = "344232c153";
const PIN_RELEASE = "5.2.3 (Build: 20260914)";
const FORMAT_HTML = 1;
const MOODLE_ROOT = "/var/www/html";
const DATAROOT = "/var/www/moodledata";
const CONFIG_PATH = MOODLE_ROOT . "/config.php";
const DRAFT_ROOT = DATAROOT . "/draft";
const TEMP_PARENT = DATAROOT . "/temp/bbquiz_import";
const JOIN_NEEDLE = '$fullpath = $this->filebase . \'/\' . $path;';
const GET_FILECONTENT_NEEDLE = "clean_param(\$path, PARAM_PATH)";

bootstrap_lab();

$path = parse_url($_SERVER["REQUEST_URI"] ?? "/", PHP_URL_PATH);
if (!is_string($path) || $path === "") {
    $path = "/";
}

try {
    route($path);
} catch (Throwable $exc) {
    send_json(500, [
        "error" => $exc->getMessage(),
        "class" => $exc::class,
    ]);
}

function bootstrap_lab(): void
{
    foreach ([MOODLE_ROOT, DATAROOT . "/temp", DRAFT_ROOT, TEMP_PARENT] as $dir) {
        if (!is_dir($dir) && !mkdir($dir, 0777, true) && !is_dir($dir)) {
            throw new RuntimeException("mkdir-failed " . $dir);
        }
    }
    if (!is_file(CONFIG_PATH)) {
        $config = <<<PHP
<?php
unset(\$CFG);
\$CFG = new stdClass();
\$CFG->dbtype = 'mariadb';
\$CFG->dbname = 'moodle';
\$CFG->dbuser = 'moodle';
\$CFG->dbpass = 'lab-db-password-not-a-shell';
\$CFG->wwwroot = 'http://127.0.0.1:19560';
\$CFG->dataroot = '/var/www/moodledata';
\$CFG->lab_witness = 'MOODLE-BLACKBOARD-IMG-WITNESS';
PHP;
        if (file_put_contents(CONFIG_PATH, $config) === false) {
            throw new RuntimeException("config-write-failed");
        }
    }
}

function route(string $path): void
{
    if ($path === "/ping") {
        send_json(200, meta_payload(["pong" => "pong"]));
    }
    if ($path === "/meta") {
        send_json(200, meta_payload());
    }
    if ($path === "/pin/formatbase.php") {
        send_text(200, pin_file("formatbase.php"));
    }
    if ($path === "/pin/format.php") {
        send_text(200, pin_file("format.php"));
    }
    if ($path === "/import") {
        handle_import();
    }
    if ($path === "/draft") {
        handle_draft();
    }
    send_json(404, ["error" => "not-found", "path" => $path]);
}

/**
 * @param array<string, mixed> $extra
 * @return array<string, mixed>
 */
function meta_payload(array $extra = []): array
{
    $pin = pin_file("formatbase.php");
    $format = pin_file("format.php");
    $base = [
        "ok" => true,
        "version" => PIN_RELEASE,
        "tag" => PIN_TAG,
        "sha" => PIN_SHA,
        "config_path" => CONFIG_PATH,
        "img_src" => default_img_src(),
        "pin_join" => str_contains($pin, JOIN_NEEDLE),
        "pin_get_filecontent_jailed" => str_contains($format, GET_FILECONTENT_NEEDLE),
        "config_sha256" => hash_file("sha256", CONFIG_PATH),
        "config_len" => filesize(CONFIG_PATH),
    ];
    return array_merge($base, $extra);
}

function pin_file(string $name): string
{
    $full = __DIR__ . "/pin-src/" . $name;
    if (!is_file($full)) {
        throw new RuntimeException("pin-file-missing " . $name);
    }
    $body = file_get_contents($full);
    if ($body === false) {
        throw new RuntimeException("pin-file-read " . $name);
    }
    return $body;
}

function handle_import(): void
{
    if (($_SERVER["REQUEST_METHOD"] ?? "") !== "POST") {
        send_json(405, ["error" => "method"]);
    }
    $role = (string) ($_POST["role"] ?? "");
    if ($role !== "teacher") {
        send_json(403, [
            "error" => "teacher-only",
            "role" => $role,
        ]);
    }
    if (!isset($_FILES["zip"]) || !is_array($_FILES["zip"])) {
        send_json(400, ["error" => "missing-zip"]);
    }
    $tmp = (string) ($_FILES["zip"]["tmp_name"] ?? "");
    $err = (int) ($_FILES["zip"]["error"] ?? UPLOAD_ERR_NO_FILE);
    if ($err !== UPLOAD_ERR_OK || $tmp === "" || !is_readable($tmp)) {
        send_json(400, ["error" => "zip-upload", "code" => $err]);
    }
    $jail = ((string) ($_POST["jail"] ?? "0")) === "1";
    $result = teacher_import_zip($tmp, $jail);
    send_json(200, $result);
}

/**
 * @return array<string, mixed>
 */
function teacher_import_zip(string $zippath, bool $jail): array
{
    $tempdir = TEMP_PARENT . "/" . bin2hex(random_bytes(4));
    if (!mkdir($tempdir, 0777, true) && !is_dir($tempdir)) {
        throw new RuntimeException("tempdir-failed");
    }
    $zip = new ZipArchive();
    if ($zip->open($zippath) !== true) {
        throw new RuntimeException("zip-open-failed");
    }
    $zip->extractTo($tempdir);
    $zip->close();

    $html = find_question_html($tempdir);
    $importer = new qformat_blackboard_six_base();
    $importer->filebase = $tempdir;
    $importer->tempdir = $tempdir;
    $importer->jail = $jail;
    $data = $importer->text_field($html);

    $config = (string) file_get_contents(CONFIG_PATH);
    $itemid = isset($data["itemid"]) ? (string) $data["itemid"] : "";
    $filename = isset($data["draft_filename"]) ? (string) $data["draft_filename"] : "";
    $draftpath = isset($data["stored"]) ? (string) $data["stored"] : "";
    $draft = ($draftpath !== "" && is_readable($draftpath))
        ? (string) file_get_contents($draftpath)
        : "";
    $match = $draft !== "" && hash("sha256", $draft) === hash("sha256", $config);
    $src = default_img_src();
    if (preg_match('|<img[^>]+src="([^"]*)"|i', $html, $src_match) === 1) {
        $src = $src_match[1];
    }
    $used = $jail ? clean_param_path($src) : $src;
    $under = path_jailed_under_filebase($tempdir, $used);

    return [
        "ok" => true,
        "how" => "gadget",
        "role" => "teacher",
        "jail" => $jail,
        "itemid" => $itemid,
        "draft_filename" => $filename,
        "draft_len" => strlen($draft),
        "config_len" => strlen($config),
        "match" => $match,
        "witness_in_draft" => str_contains($draft, WITNESS),
        "pluginfile" => (string) ($data["text"] ?? ""),
        "readable" => isset($data["readable"]) ? (bool) $data["readable"] : false,
        "jailed_under_filebase" => $under,
        "img_src" => $src,
        "cleaned_src" => $used,
        "config_sha256" => hash("sha256", $config),
        "draft_sha256" => $draft === "" ? "" : hash("sha256", $draft),
    ];
}

function find_question_html(string $tempdir): string
{
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($tempdir, FilesystemIterator::SKIP_DOTS),
    );
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $body = (string) file_get_contents($file->getPathname());
        if (preg_match('|<img[^>]+src="([^"]*)"|i', $body) === 1) {
            if (preg_match('/<!\\[CDATA\\[(.*?)\\]\\]>/s', $body, $cdata) === 1) {
                return $cdata[1];
            }
            return $body;
        }
    }
    throw new RuntimeException("no-img-src-in-zip");
}

function handle_draft(): void
{
    $itemid = (string) ($_GET["itemid"] ?? "");
    $filename = (string) ($_GET["filename"] ?? "");
    if ($itemid === "" || $filename === "") {
        send_json(400, ["error" => "missing-draft-args"]);
    }
    if ($itemid !== clean_param_file($itemid) || $filename !== clean_param_file($filename)) {
        send_json(400, ["error" => "bad-draft-args"]);
    }
    $full = DRAFT_ROOT . "/" . $itemid . "/" . $filename;
    if (!is_readable($full)) {
        send_json(404, ["error" => "draft-missing"]);
    }
    header("Content-Type: application/octet-stream");
    header("Content-Length: " . (string) filesize($full));
    readfile($full);
    exit;
}

function default_img_src(): string
{
    // Same depth as the per-import extract dir under TEMP_PARENT.
    return relative_from_dir(TEMP_PARENT . "/run", CONFIG_PATH);
}

/**
 * @param list<string> $parts
 * @return list<string>
 */
function split_abs(string $path): array
{
    $parts = explode("/", trim($path, "/"));
    return array_values(array_filter($parts, static fn(string $p): bool => $p !== ""));
}

function relative_from_dir(string $from_dir, string $to_file): string
{
    $from = split_abs($from_dir);
    $to = split_abs($to_file);
    while ($from !== [] && $to !== [] && $from[0] === $to[0]) {
        array_shift($from);
        array_shift($to);
    }
    return str_repeat("../", count($from)) . implode("/", $to);
}

function path_jailed_under_filebase(string $filebase, string $path): bool
{
    $candidate = $filebase . "/" . $path;
    $real = realpath($candidate);
    $base = realpath($filebase);
    if ($real === false || $base === false) {
        return true;
    }
    $base = rtrim($base, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    return str_starts_with($real, $base);
}

/**
 * Moodle PARAM_FILE (public/lib/classes/param.php clean_param_value_file).
 */
function clean_param_file(string $param): string
{
    // phpcs:ignore moodle.Strings.ForbiddenStrings.Found
    $param = preg_replace('~[[:cntrl:]]|[&<>"`\|\':\\\\/]~u', '', $param) ?? "";
    if ($param === "." || $param === "..") {
        return "";
    }
    return $param;
}

/**
 * Moodle PARAM_PATH (public/lib/classes/param.php clean_param_value_path).
 * get_filecontent() uses this; text_field() does not.
 */
function clean_param_path(string $param): string
{
    $param = str_replace("\\", "/", $param);
    $breadcrumb = explode("/", $param);
    foreach ($breadcrumb as $key => $crumb) {
        if (!($crumb === "." && $key === 0)) {
            $crumb = clean_param_file($crumb);
        }
        $breadcrumb[$key] = $crumb;
    }
    $param = implode("/", $breadcrumb);
    $param = preg_replace("~//+~", "/", $param) ?? $param;
    $param = preg_replace("~/(\\./)+~", "/", $param) ?? $param;
    return $param;
}

/**
 * Pin: public/question/format/blackboard_six/formatbase.php 96-145.
 */
class qformat_blackboard_six_base
{
    public string $filebase = "";
    public string $tempdir = "";
    public bool $jail = false;

    /**
     * @param array<string, mixed> $text
     */
    protected function store_file_for_text_field(
        array &$text,
        string $tempdir,
        string $filepathinsidetempdir,
        string $filename,
    ): string {
        if (empty($text["itemid"])) {
            $text["itemid"] = bin2hex(random_bytes(8));
        }
        $newfilename = clean_param_file(
            str_replace("/", "__", $filepathinsidetempdir . "__" . $filename),
        );
        $src = $tempdir . "/" . $filepathinsidetempdir . "/" . $filename;
        $dest_dir = DRAFT_ROOT . "/" . $text["itemid"];
        if (!is_dir($dest_dir) && !mkdir($dest_dir, 0777, true) && !is_dir($dest_dir)) {
            throw new RuntimeException("draft-mkdir");
        }
        $dest = $dest_dir . "/" . $newfilename;
        if (!copy($src, $dest)) {
            throw new RuntimeException("draft-copy");
        }
        $text["stored"] = $dest;
        $text["draft_filename"] = $newfilename;
        return $newfilename;
    }

    /**
     * @return array<string, mixed>
     */
    public function text_field(string $text): array
    {
        $data = [];
        preg_match_all('|<img[^>]+src="([^"]*)"|i', $text, $out);
        $filepaths = [];
        foreach ($out[1] as $path) {
            $used = $this->jail ? clean_param_path($path) : $path;
            $fullpath = $this->filebase . "/" . $used;
            $data["readable"] = is_readable($fullpath);
            if (is_readable($fullpath) && !in_array($path, $filepaths, true)) {
                $dirpath = dirname($used);
                $filename = basename($used);
                $newfilename = $this->store_file_for_text_field(
                    $data,
                    $this->filebase,
                    $dirpath,
                    $filename,
                );
                $text = preg_replace("|" . preg_quote($path, "|") . "|", "@@PLUGINFILE@@/" . $newfilename, $text) ?? $text;
                $filepaths[] = $path;
            }
        }
        $data["text"] = $text;
        $data["format"] = FORMAT_HTML;
        return $data;
    }
}

/**
 * @param array<string, mixed> $payload
 */
function send_json(int $status, array $payload): void
{
    http_response_code($status);
    header("Content-Type: application/json; charset=utf-8");
    echo json_encode($payload, JSON_UNESCAPED_SLASHES);
    exit;
}

function send_text(int $status, string $body): void
{
    http_response_code($status);
    header("Content-Type: text/plain; charset=utf-8");
    echo $body;
    exit;
}
