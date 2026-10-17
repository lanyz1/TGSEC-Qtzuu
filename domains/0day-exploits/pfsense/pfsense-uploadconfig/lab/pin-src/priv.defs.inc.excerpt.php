<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

$priv_list['page-diagnostics-backup-restore'] = array();
$priv_list['page-diagnostics-backup-restore']['name'] = gettext("WebCfg - Diagnostics: Backup & Restore");
$priv_list['page-diagnostics-backup-restore']['descr'] = gettext("Allow access to the 'Diagnostics: Backup & Restore' page.");
$priv_list['page-diagnostics-backup-restore']['warn'] = "standard-warning-root";
$priv_list['page-diagnostics-backup-restore']['match'] = array();
$priv_list['page-diagnostics-backup-restore']['match'][] = "diag_backup.php*";

$priv_list['page-hidden-uploadconfiguration'] = array();
$priv_list['page-hidden-uploadconfiguration']['name'] = gettext("WebCfg - Hidden: Upload Configuration");
$priv_list['page-hidden-uploadconfiguration']['descr'] = gettext("Allow access to the 'Hidden: Upload Configuration' page.");
$priv_list['page-hidden-uploadconfiguration']['match'] = array();
$priv_list['page-hidden-uploadconfiguration']['match'][] = "uploadconfig.php*";
