<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function captiveportal_write_elements() {
	global $g, $cpzone;

	$cpcfg = config_get_path("captiveportal/{$cpzone}", []);

	if (!is_dir(g_get('captiveportal_element_path'))) {
		@mkdir(g_get('captiveportal_element_path'));
	}

	if (is_array($cpcfg['element'])) {
		foreach ($cpcfg['element'] as $data) {
			/* Do not attempt to decode or write out empty files. */
			if (isset($data['nocontent'])) {
					continue;
			}
			if (empty($data['content']) || empty(base64_decode($data['content']))) {
				unlink_if_exists("{$g['captiveportal_element_path']}/{$data['name']}");
				touch("{$g['captiveportal_element_path']}/{$data['name']}");
			} elseif (!@file_put_contents("{$g['captiveportal_element_path']}/{$data['name']}", base64_decode($data['content']))) {
				printf(gettext('Error: cannot open \'%1$s\' in captiveportal_write_elements()%2$s'), $data['name'], "\n");
				return 1;
			}
			if (!file_exists("{$g['captiveportal_path']}/{$data['name']}")) {
				@symlink("{$g['captiveportal_element_path']}/{$data['name']}", "{$g['captiveportal_path']}/{$data['name']}");
			}
		}
	}

	return 0;
}
