<?php

declare(strict_types=1);

$cfg['blowfish_secret'] = 'pma-config-set-2fa-lab-secret-32';
$cfg['TempDir'] = '/tmp/pma';

// Lab-only: expose the Simple 2FA backend so Settings can enroll without a key.
// The leftover is POST /config/set persisting key=2fa, not this flag.
$cfg['DBG']['simple2fa'] = true;

$i = 0;
$i++;
$cfg['Servers'][$i]['auth_type'] = 'cookie';
$cfg['Servers'][$i]['host'] = 'db';
$cfg['Servers'][$i]['compress'] = false;
$cfg['Servers'][$i]['AllowNoPassword'] = false;
$cfg['Servers'][$i]['controluser'] = 'pma';
$cfg['Servers'][$i]['controlpass'] = 'pmapass';
$cfg['Servers'][$i]['pmadb'] = 'phpmyadmin';
$cfg['Servers'][$i]['userconfig'] = 'pma__userconfig';
