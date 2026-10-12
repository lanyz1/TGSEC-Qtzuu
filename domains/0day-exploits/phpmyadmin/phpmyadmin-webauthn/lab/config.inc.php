<?php

declare(strict_types=1);

$cfg['blowfish_secret'] = 'pma-webauthn-lab-secret-32bytes!!';
$cfg['TempDir'] = '/tmp/pma';

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
