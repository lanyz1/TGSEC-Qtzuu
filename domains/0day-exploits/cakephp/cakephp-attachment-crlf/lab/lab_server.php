<?php
declare(strict_types=1);

/**
 * Loopback oracle for CakePHP 5.4.2 attachment Content-Type / Content-ID CRLF.
 * Serves pin sources and Message::setAttachments MIME bodies. No SMTP send.
 */

require __DIR__ . '/pin/vendor/autoload.php';

use Cake\Core\Configure;
use Cake\Mailer\Message;
use Laminas\Diactoros\UploadedFile;

const WITNESS = 'CAKEPHP-ATTACHMENT-CRLF-WITNESS';
const PIN_VERSION = '5.4.2';
const PIN_SHA = '887b641de9f7aba06071f98f17edcbc573cbcf63';
const PIN_ROOT = '/lab/pin';

Configure::write('App.encoding', 'UTF-8');

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
            'version' => PIN_VERSION,
            'sha' => pin_sha(),
            'pong' => 'pong',
        ]);
    }

    if ($path === '/pin/VERSION.txt') {
        send_text(200, pin_file('VERSION.txt'));
    }
    if ($path === '/pin/FormDataPart.php') {
        send_text(200, pin_file('src/Http/Client/FormDataPart.php'));
    }
    if ($path === '/pin/Message.php') {
        send_text(200, pin_file('src/Mailer/Message.php'));
    }

    if ($path === '/oracle') {
        $case = $_GET['case'] ?? '';
        if (!is_string($case) || $case === '') {
            send_json(400, ['error' => 'missing-case']);
        }
        send_json(200, run_case($case));
    }

    send_json(404, ['error' => 'not-found', 'path' => $path]);
}

function pin_sha(): string
{
    $rev = trim((string)shell_exec('git -C ' . escapeshellarg(PIN_ROOT) . ' rev-parse HEAD'));
    return $rev !== '' ? $rev : PIN_SHA;
}

function pin_file(string $rel): string
{
    $full = PIN_ROOT . '/' . $rel;
    if (!is_file($full)) {
        throw new RuntimeException('pin-file-missing ' . $rel);
    }
    $body = file_get_contents($full);
    if ($body === false) {
        throw new RuntimeException('pin-file-read ' . $rel);
    }
    return $body;
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

function make_message(): Message
{
    $message = new Message();
    $message->setFrom('lab@localhost.invalid');
    $message->setTo('sink@localhost.invalid');
    $message->setSubject('attachment-crlf-lab');
    $message->setMessageId(false);
    $message->setDomain('localhost.invalid');
    $message->setBodyText('lab');

    return $message;
}

function run_case(string $case): array
{
    $message = make_message();
    $injected = 'X-Injected: ' . WITNESS;
    $filename = "lab.txt\r\n" . $injected;
    $mimetype = "text/plain\r\n" . $injected;
    $contentId = "cid@localhost.invalid>\r\n" . $injected . "\r\nX-Dummy: x";

    switch ($case) {
        case 'filename':
            $message->setAttachments([
                $filename => [
                    'data' => 'lab-body',
                    'mimetype' => 'text/plain',
                ],
            ]);
            break;
        case 'mimetype':
            $message->setAttachments([
                'lab.bin' => [
                    'data' => 'lab-body',
                    'mimetype' => $mimetype,
                ],
            ]);
            break;
        case 'contentId':
            $message->setAttachments([
                'lab.bin' => [
                    'data' => 'lab-body',
                    'mimetype' => 'image/png',
                    'contentId' => $contentId,
                ],
            ]);
            break;
        case 'upload':
            $tmp = tempnam(sys_get_temp_dir(), 'cake');
            if ($tmp === false) {
                throw new RuntimeException('tempnam-failed');
            }
            file_put_contents($tmp, 'lab-body');
            $upload = new UploadedFile(
                $tmp,
                (int)filesize($tmp),
                UPLOAD_ERR_OK,
                'upload.bin',
                $mimetype,
            );
            $message->setAttachments([$upload]);
            break;
        default:
            send_json(400, ['error' => 'unknown-case', 'case' => $case]);
    }

    return [
        'case' => $case,
        'version' => PIN_VERSION,
        'sha' => pin_sha(),
        'body' => $message->getBodyString(),
    ];
}
