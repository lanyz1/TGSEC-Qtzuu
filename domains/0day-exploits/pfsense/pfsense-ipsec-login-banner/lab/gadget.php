<?php
/**
 * Pinned ipsec_strongswan_confgen() gadget.
 * pfSense CE 2.9.0-DEVELOPMENT pin 9363ac5b8651a1c7a333180425ce7719070f95f9
 * src/etc/inc/ipsec.inc:1361-1388 plus attr.28672 assignment :1842-1844.
 */

/****f* ipsec/ipsec_strongswan_confgen
 * NAME
 *   ipsec_strongswan_confgen - Generate strongswan.conf style formatted output
 *                              From a multi-dimensional array.
 * INPUTS
 *   $confarr: An array of key=value pairs or key=array entries for subsections.
 *   $indent : A string of tabs used when indenting lines.
 * RESULT
 *   Returns a string of key=value pairs with proper indenting, and with named
 *   subsections enclosed in braces.
 * NOTES
 *   Values starting with a "#" (comments) or "include " will be printed
 *   directly without their associated key name.
 ******/
function ipsec_strongswan_confgen($confarr, $indent = "") {
	$confstr = "";
	/* Only process the contents if it's an array. */
	if (is_array($confarr)) {
		foreach ($confarr as $key => $value) {
			if (is_array($value)) {
				/* If the array is empty, do not print anything */
				if (empty($value)) {
					continue;
				}
				/* If this is an array, setup the subsection name
				 * and structure, then call this function
				 * recursively to walk the lower array. */
				$confstr .= "{$indent}{$key} {\n";
				$confstr .= ipsec_strongswan_confgen($value, $indent . "\t");
				$confstr .= "{$indent}}\n";
			} else {
				$confstr .= "{$indent}";
				if ((substr($value, 0 , 1) != '#') &&
				    (substr($value, 0 , 8) != 'include ')) {
					/* Not a comment or include, print the key */
					$confstr .= "{$key} = ";
				}
				$confstr .= "{$value}\n";
			}
		}
	}
	return $confstr;
}

if ($argc < 3) {
	fwrite(STDERR, "usage: gadget.php BANNER_FILE OUT_CONF\n");
	exit(2);
}

$banner_file = $argv[1];
$out_conf = $argv[2];
$login_banner = file_get_contents($banner_file);
if ($login_banner === false) {
	fwrite(STDERR, "read-banner-failed\n");
	exit(2);
}
$login_banner = str_replace("\r\n", "\n", $login_banner);
$login_banner = rtrim($login_banner, "\n");
if (!strlen($login_banner)) {
	fwrite(STDERR, "empty-banner\n");
	exit(2);
}

/* Minimal $ssconf matching production order on this pin:
 * starter, charon keys, syslog, plugins unity/curve25519, attr with 28672 last.
 * save_passwd / pfs_group left off so 28672 is last in attr.
 */
$ssconf = array();
$ssconf[] = "# Automatically generated config file - DO NOT MODIFY. Changes will be overwritten.";
$ssconf['starter'] = array();
$ssconf['starter']['load_warning'] = "no";

$ssconf['charon'] = array();
$ssconf['charon'][] = '# number of worker threads in charon';
$ssconf['charon']['threads'] = '16';
$ssconf['charon']['ikesa_table_size'] = '32';
$ssconf['charon']['ikesa_table_segments'] = '4';
$ssconf['charon']['init_limit_half_open'] = '1000';
$ssconf['charon']['install_routes'] = 'no';
$ssconf['charon']['load_modular'] = 'yes';
$ssconf['charon']['ignore_acquire_ts'] = 'yes';
$ssconf['charon']['cisco_unity'] = 'no';

$ssconf['charon']['syslog'] = array();
$ssconf['charon']['syslog']['identifier'] = 'charon';
$ssconf['charon']['syslog'][] = "# log everything under daemon since it ends up in the same place regardless with our syslog.conf";
$ssconf['charon']['syslog']['daemon'] = array();
$ssconf['charon']['syslog']['daemon']['ike_name'] = 'yes';
$ssconf['charon']['syslog'][] = '# disable logging under auth so logs aren\'t duplicated';
$ssconf['charon']['syslog']['auth'] = array();
$ssconf['charon']['syslog']['auth']['default'] = -1;

$ssconf['charon']['plugins'] = array();
$ssconf['charon']['plugins'][] = "# Load defaults";
$ssconf['charon']['plugins'][] = "include /etc/strongswan.d/charon/*.conf";
$ssconf['charon']['plugins']['unity'] = array('load' => 'no');
$ssconf['charon']['plugins']['curve25519'] = array('load' => "yes");

$ssconf['charon']['plugins']['attr'] = array();
$ssconf['charon']['plugins']['attr'][] = "# Login Banner";
$ssconf['charon']['plugins']['attr']['28672'] = $login_banner;

$conf = ipsec_strongswan_confgen($ssconf);
if (file_put_contents($out_conf, $conf) === false) {
	fwrite(STDERR, "write-conf-failed\n");
	exit(2);
}

fprintf(STDOUT, "gadget-ok bytes=%d banner_len=%d out=%s\n", strlen($conf), strlen($login_banner), $out_conf);
