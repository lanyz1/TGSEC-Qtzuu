<?php
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use Cake\Core\Configure;
use Cake\Http\Middleware\HttpsEnforcerMiddleware;
use Cake\Http\ServerRequest;
use Cake\Http\ServerRequestFactory;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

const LAB_WITNESS = 'CAKEPHP-TRUSTED-PROXIES-WITNESS';
const PINNED_VERSION = '5.4.2';
const LISTED_PROXY = '10.0.0.1';

function cakephp_version(): string
{
    $path = __DIR__ . '/vendor/cakephp/cakephp/VERSION.txt';
    if (!is_file($path)) {
        return 'missing';
    }
    $version = 'unknown';
    foreach (file($path, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '/') || str_starts_with($line, '*')) {
            continue;
        }
        $version = $line;
    }
    return $version;
}

function emit(ResponseInterface $response): void
{
    http_response_code($response->getStatusCode());
    foreach ($response->getHeaders() as $name => $values) {
        foreach ($values as $index => $value) {
            header(sprintf('%s: %s', $name, $value), $index === 0);
        }
    }
    echo (string)$response->getBody();
}

function json_ok(array $payload, int $status = 200): JsonResponse
{
    return new JsonResponse($payload, $status, ['Cache-Control' => 'no-store']);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$version = cakephp_version();

if ($path === '/health') {
    emit(json_ok([
        'ok' => true,
        'cakephp' => $version,
        'pin' => PINNED_VERSION,
    ]));
    exit(0);
}

Configure::write('debug', false);

try {
    $request = ServerRequestFactory::fromGlobals();
} catch (Throwable $exc) {
    emit(json_ok([
        'ok' => false,
        'error' => 'request-factory-failed',
        'class' => $exc::class,
    ], 500));
    exit(0);
}

$trusted = $path !== '/control';
$config = [
    'redirect' => true,
    'statusCode' => 301,
    'disableOnDebug' => false,
];
if ($trusted) {
    $config['trustedProxies'] = [LISTED_PROXY];
}

$middleware = new HttpsEnforcerMiddleware($config);
$handler = new class ($version, $trusted) implements RequestHandlerInterface {
    public function __construct(
        private readonly string $version,
        private readonly bool $trusted,
    ) {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if (!$request instanceof ServerRequest) {
            return json_ok(['ok' => false, 'error' => 'not-cake-request'], 500);
        }
        return json_ok([
            'ok' => true,
            'mode' => $this->trusted ? 'trusted' : 'control',
            'cakephp' => $this->version,
            'pin' => PINNED_VERSION,
            'scheme' => $request->scheme(),
            'uri_scheme' => $request->getUri()->getScheme(),
            'host' => $request->host(),
            'client_ip' => $request->clientIp(),
            'remote_addr' => $request->getEnv('REMOTE_ADDR'),
            'trust_proxy' => $request->trustProxy,
            'trusted_proxies' => $request->getTrustedProxies(),
            'listed_proxy' => LISTED_PROXY,
            'witness' => LAB_WITNESS,
        ]);
    }
};

try {
    emit($middleware->process($request, $handler));
} catch (Throwable $exc) {
    emit(json_ok([
        'ok' => false,
        'error' => 'middleware-failed',
        'class' => $exc::class,
    ], 500));
}
