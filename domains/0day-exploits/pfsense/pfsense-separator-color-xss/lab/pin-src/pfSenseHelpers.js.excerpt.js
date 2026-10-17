/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */
/* src/usr/local/www/js/pfSenseHelpers.js separator color buttons and save_separators. */

gColor = 'bg-info';

		'&nbsp;&nbsp;<a id="sepclrblue" value="bg-info"><i class="fa-solid fa-circle text-info icon-pointer"></i></a>' +
		'&nbsp;&nbsp;<a id="sepclrred" value="bg-danger"><i class="fa-solid fa-circle text-danger icon-pointer"></i></a>' +
		'&nbsp;&nbsp;<a id="sepclrgreen" value="bg-success"><i class="fa-solid fa-circle text-success icon-pointer"></i></a>' +
		'&nbsp;&nbsp;<a id="sepclrorange" value="bg-warning"><i class="fa-solid fa-circle text-warning icon-pointer"></i></button>' +

			sepinput = '<input type="hidden" name="separator[' + sepnum + '][row]" value="' + seprow + '"></input>';
			sepinput = '<input type="hidden" name="separator[' + sepnum + '][text]" value="' + escapeHtml($(this).find('td').text()) + '"></input>';
			sepinput = '<input type="hidden" name="separator[' + sepnum + '][color]" value="' + $(this).find('td').prop('class') + '"></input>';
			sepinput = '<input type="hidden" name="separator[' + sepnum + '][if]" value="' + iface + '"></input>';
