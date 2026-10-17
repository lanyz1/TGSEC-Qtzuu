<?php
/* Pin excerpt simplepie/simplepie 76cccb1b2c5dcaf44f304c925ab30c0f48643992 (1.9.0). Do not edit by hand. */

    public static function fix_protocol(string $url, int $http = 1)
    {
        $url = Misc::normalize_url($url);
        $parsed = Misc::parse_url($url);
        if ($parsed['scheme'] !== '' && $parsed['scheme'] !== 'http' && $parsed['scheme'] !== 'https') {
            return Misc::fix_protocol(Misc::compress_parse_url('http', $parsed['authority'], $parsed['path'], $parsed['query'], $parsed['fragment']), $http);
        }

        if ($parsed['scheme'] === '' && $parsed['authority'] === '' && !file_exists($url)) {
            return Misc::fix_protocol(Misc::compress_parse_url('http', $parsed['path'], '', $parsed['query'], $parsed['fragment']), $http);
        }

        if ($http === 2 && $parsed['scheme'] !== '') {
            return "feed:$url";
        } elseif ($http === 3 && strtolower($parsed['scheme']) === 'http') {
            return substr_replace($url, 'podcast', 0, 4);
        } elseif ($http === 4 && strtolower($parsed['scheme']) === 'http') {
            return substr_replace($url, 'itpc', 0, 4);
        }

        return $url;
    }
