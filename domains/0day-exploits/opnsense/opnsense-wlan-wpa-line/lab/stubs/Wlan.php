<?php

namespace OPNsense\Interfaces;

/**
 * Stand-in for the MVC Wlan model. Lab supplies getConfig() from the gadget.
 */
class Wlan
{
    /** @var array<string, mixed> */
    public static $lab_config = [];

    /**
     * @param string $device
     * @return array<string, mixed>
     */
    public function getConfig($device)
    {
        return self::$lab_config;
    }
}
