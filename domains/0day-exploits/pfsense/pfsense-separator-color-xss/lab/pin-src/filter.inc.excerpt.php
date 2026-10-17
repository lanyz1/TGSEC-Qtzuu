<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */
/* src/etc/inc/filter.inc display_separator / separator_rows */

/* display rules separators */
function display_separator($separators, $nrules, $columns_in_table) {
	if (is_array($separators)) {
		foreach ($separators as $separator) {
			if (empty($separator)) {
				continue;
			}
			if (array_get_path($separator, 'row/0') == "fr" . $nrules) {
				$cellcolor = $separator['color'];
				print('<tr class="ui-sortable-handle separator">' .
					'<td class="' . $cellcolor . '" colspan="' . ($columns_in_table -1) . '">' . '<span class="' . $cellcolor . '">' . htmlspecialchars($separator['text']) . '</span></td>' .
					'<td  class="' . $cellcolor . '"><a href="#"><i class="fa-solid fa-trash-can no-confirm sepdel" title="' . gettext("delete this separator") . '"></i></a></td>' .
					'</tr>' . "\n");
			}
		}
	}
}

/* Return a list of separator rows */
function separator_rows($separators) {
	$seprows = [];
	if (is_array($separators)) {
		foreach ($separators as $separator) {
			if (empty($separator)) {
				continue;
			}
			$seprows[substr(array_get_path($separator, 'row/0'), 2)] = true;
		}
	}
	return $seprows;
}
