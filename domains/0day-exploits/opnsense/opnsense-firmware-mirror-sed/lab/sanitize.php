<?php

declare(strict_types=1);

/**
 * Pin 26.7.6 FirmwareController::setAction FILTER_SANITIZE_URL loop (L987-L993).
 *
 * @param array<string, mixed> $values
 * @return array<string, mixed>
 */
function firmware_set_sanitize(array $values): array
{
    foreach ($values as $key => &$value) {
        if ($key == 'plugins') {
            /* discards plugins on purpose for the time being */
            unset($values[$key]);
        } else {
            $value = filter_var($value, FILTER_SANITIZE_URL);
        }
    }
    unset($value);
    return $values;
}
