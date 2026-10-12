<?php
/**
 * Console bootstrap so user_ldap is loaded. Prints JSON flags for the oracle.
 */
define('OC_CONSOLE', 1);
require_once '/var/www/html/lib/base.php';
\OCP\Server::get(\OCP\App\IAppManager::class)->loadApps();

$gm = \OCP\Server::get(\OCP\IGroupManager::class);
$um = \OCP\Server::get(\OCP\IUserManager::class);
$uid = getenv('NC_LDAP_UID') ?: 'ldapadmin';
$help = getenv('NC_HELPDESK_USER') ?: 'helpdesk';
$target = $um->get($uid);
$actor = $um->get($help);
if ($target === null || $actor === null) {
	fwrite(STDERR, 'missing user target=' . ($target ? 'ok' : 'null') . ' actor=' . ($actor ? 'ok' : 'null') . PHP_EOL);
	echo json_encode(['error' => 'missing', 'target' => $uid, 'actor' => $help], JSON_UNESCAPED_SLASHES), "\n";
	exit(2);
}
$out = [
	'target' => $uid,
	'target_isAdmin' => $gm->isAdmin($uid),
	'target_isInGroupAdmin' => $gm->isInGroup($uid, 'admin'),
	'target_groups' => $gm->getUserGroupIds($target),
	'actor' => $help,
	'actor_isAdmin' => $gm->isAdmin($help),
	'actor_isDelegatedAdmin' => $gm->isDelegatedAdmin($help),
	'actor_isInGroupAdmin' => $gm->isInGroup($help, 'admin'),
	'actor_groups' => $gm->getUserGroupIds($actor),
];
echo json_encode($out, JSON_UNESCAPED_SLASHES), "\n";
