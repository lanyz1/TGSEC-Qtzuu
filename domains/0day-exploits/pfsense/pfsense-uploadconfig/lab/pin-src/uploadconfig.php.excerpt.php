<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

##|+PRIV
##|*IDENT=page-hidden-uploadconfiguration
##|*NAME=Hidden: Upload Configuration
##|*DESCR=Allow access to the 'Hidden: Upload Configuration' page.
##|*MATCH=uploadconfig.php*
##|-PRIV

function uploadconfig_handle() {
	global $g;

	header("Content-Type: text/plain");

	/* get config.xml in POST variable "config" */
	if ($_POST['config']) {
		$fd = @fopen("{$g['tmp_path']}/config.xml", "w");
		if (!$fd) {
			echo gettext("ERR Could not save configuration.")."\n";
			return;
		}
		fwrite($fd, $_POST['config']);
		fclose($fd);
		if (config_install("{$g['tmp_path']}/config.xml") == 0) {
			echo gettext("OK")."\n";
			system_reboot();
		} else {
			echo gettext("ERR Could not install configuration.")."\n";
		}
	} else {
		echo gettext("ERR Invalid configuration received.")."\n";
	}
}
