<?php

/*
 * Stubs for util.inc / config.inc helpers used by interfaces_wlan_configure.
 * mwexecf is a no-op so the generated setup script is never executed.
 */

function &config_read_array()
{
    static $empty = [];
    $empty = [];
    return $empty;
}

function exec_safe($format, $args = [])
{
    return '# exec_safe skipped';
}

function mwexecf($format, $args = [], $mute = false)
{
    return 0;
}

function killbypid($pid_or_file, $sig = 'TERM', $waitforit = true)
{
}

function shell_safe($format, $args = [], $explode = false, $separator = "\n")
{
    return $explode ? [] : '';
}

function log_msg($msg, $prio = 0)
{
}
