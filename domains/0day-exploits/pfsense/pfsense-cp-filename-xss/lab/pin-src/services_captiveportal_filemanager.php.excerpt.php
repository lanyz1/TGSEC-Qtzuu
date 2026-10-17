<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function filemanager_upload_stored_name() {
		if ((!stristr($_FILES['new']['name'], "captiveportal-")) && ($_FILES['new']['name'] != 'favicon.ico')) {
			$name = "captiveportal-" . $_FILES['new']['name'];
		} else {
			$name = $_FILES['new']['name'];
		}
		return $name;
}

function filemanager_installed_name_html($element) {
							return htmlspecialchars($element['name']);
}
