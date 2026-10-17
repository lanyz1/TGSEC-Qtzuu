<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

##|+PRIV
##|*IDENT=page-services-captiveportal-filemanager
##|*NAME=Services: Captive Portal: File Manager
##|*DESCR=Allow access to the 'Services: Captive Portal: File Manager' page.
##|*MATCH=services_captiveportal_filemanager.php*
##|-PRIV

function filemanager_assign_upload_name() {
	if ((!stristr($_FILES['new']['name'], "captiveportal-")) && ($_FILES['new']['name'] != 'favicon.ico')) {
		$name = "captiveportal-" . $_FILES['new']['name'];
	} else {
		$name = $_FILES['new']['name'];
	}
	return $name;
}

function filemanager_store_uploaded_file() {
	global $cpzone;

	$name = filemanager_assign_upload_name();
	$size = filesize($_FILES['new']['tmp_name']);

	$element = array();
	$element['name'] = $name;
	$element['size'] = $size;
	$element['content'] = base64_encode(file_get_contents($_FILES['new']['tmp_name']));

	config_set_path("captiveportal/{$cpzone}/element/", $element);
	cpelements_sort();

	write_config("Captive portal file manager: file uploaded");
	$write_rc = captiveportal_write_elements();
	return array($name, $write_rc);
}
