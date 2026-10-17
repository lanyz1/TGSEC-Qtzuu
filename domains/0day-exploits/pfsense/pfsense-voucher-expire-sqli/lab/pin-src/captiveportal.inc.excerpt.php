<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function captiveportal_opendb() {
	global $g, $cpzone;

	$db_path = "{$g['vardb_path']}/captiveportal{$cpzone}.db";
	$createquery = "CREATE TABLE IF NOT EXISTS captiveportal (" .
				"allow_time INTEGER, pipeno INTEGER, ip TEXT, mac TEXT, username TEXT, " .
				"sessionid TEXT, bpassword TEXT, session_timeout INTEGER, idle_timeout INTEGER, " .
				"session_terminate_time INTEGER, interim_interval INTEGER, traffic_quota INTEGER, " .
				"bw_up INTEGER, bw_down INTEGER, authmethod TEXT, context TEXT); " .
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_active ON captiveportal (sessionid, username); " .
			"CREATE INDEX IF NOT EXISTS user ON captiveportal (username); " .
			"CREATE INDEX IF NOT EXISTS ip ON captiveportal (ip); " .
			"CREATE INDEX IF NOT EXISTS starttime ON captiveportal (allow_time)";

	$DB = new SQLite3($db_path);
	$DB->busyTimeout(60000);
	if (!$DB->exec($createquery)) {
		captiveportal_syslog("Error during table {$cpzone} creation. Error message: {$DB->lastErrorMsg()}.");
	}
	return $DB;
}

/* read captive portal DB into array */
function captiveportal_read_db($query = "") {
	$cpdb = array();

	$DB = captiveportal_opendb();
	if ($DB) {
		$response = $DB->query("SELECT * FROM captiveportal {$query}");
		if ($response != FALSE) {
			while ($row = $response->fetchArray()) {
				$cpdb[] = $row;
			}
		}
		$DB->close();
	}

	return $cpdb;
}

function captiveportal_remove_entries($remove, $carp_loop = false) {
	global $cpzone;

	if (!is_array($remove) || empty($remove)) {
		return;
	}

	$query = "DELETE FROM captiveportal WHERE sessionid in (";
	foreach ($remove as $idx => $unindex) {
		$query .= "'{$unindex}'";
		if ($idx < (count($remove) - 1)) {
			$query .= ",";
		}
	}
	$query .= ")";
	captiveportal_write_db($query);

	if (captiveportal_xmlrpc_sync_get_details($syncip, $syncport, $syncuser, $syncpass, $carp_loop)) {
		$rpc_client = new pfsense_xmlrpc_client();
		$rpc_client->setConnectionData($syncip, $syncport, $syncuser, $syncpass);
		$rpc_client->set_noticefile("CaptivePortalUserSync");
		$rpc_client->xmlrpc_method('captive_portal_sync',
			array(
				'op' => 'remove_entries',
				'zone' => $cpzone,
				'entries' => base64_encode(serialize($remove))
			)
		);
	}
	return true;
}

/* write captive portal DB */
function captiveportal_write_db($queries) {
	global $g;

	if (is_array($queries)) {
		$query = implode(";", $queries);
	} else {
		$query = $queries;
	}

	$DB = captiveportal_opendb();
	if ($DB) {
		$DB->exec("BEGIN TRANSACTION");
		$result = $DB->exec($query);
		if (!$result) {
			captiveportal_syslog("Trying to modify DB returned error: {$DB->lastErrorMsg()}");
		} else {
			$DB->exec("END TRANSACTION");
		}
		$DB->close();
		return $result;
	} else {
		return true;
	}
}

/* Unauth portal login INSERT. Username is SQLite3::escapeString'd. */
function captiveportal_login_store_session($username, $password, $clientip, $clientmac, $sessionid, $allow_time, $pipeno, $attributes, $authmethod, $context) {
	$session_timeout = (!empty($attributes['session_timeout'])) ? $attributes['session_timeout'] : 'NULL';
	$idle_timeout = (!empty($attributes['idle_timeout'])) ? $attributes['idle_timeout'] : 'NULL';
	$session_terminate_time = (!empty($attributes['session_terminate_time'])) ? $attributes['session_terminate_time'] : 'NULL';
	$interim_interval = (!empty($attributes['interim_interval'])) ? $attributes['interim_interval'] : 'NULL';
	$traffic_quota = (!empty($attributes['maxbytes'])) ? $attributes['maxbytes'] : 'NULL';
	$bw_up = (!empty($attributes['bw_up'])) ? $attributes['bw_up'] : 'NULL';
	$bw_down = (!empty($attributes['bw_down'])) ? $attributes['bw_down'] : 'NULL';

	/* escape username */
	$safe_username = SQLite3::escapeString($username);

	/* encode password in Base64 just in case it contains commas */
	$bpassword = '';
	$insertquery = "INSERT INTO captiveportal (allow_time, pipeno, ip, mac, username, sessionid, bpassword, session_timeout, idle_timeout, session_terminate_time, interim_interval, traffic_quota, bw_up, bw_down, authmethod, context) ";
	$insertquery .= "VALUES ({$allow_time}, {$pipeno}, '{$clientip}', '{$clientmac}', '{$safe_username}', '{$sessionid}', '{$bpassword}', ";
	$insertquery .= "{$session_timeout}, {$idle_timeout}, {$session_terminate_time}, {$interim_interval}, {$traffic_quota}, {$bw_up}, {$bw_down}, '{$authmethod}', '{$context}')";

	/* store information to database */
	$ok = captiveportal_write_db($insertquery);
	return array(
		'ok' => $ok,
		'sql' => $insertquery,
		'safe_username' => $safe_username,
	);
}
