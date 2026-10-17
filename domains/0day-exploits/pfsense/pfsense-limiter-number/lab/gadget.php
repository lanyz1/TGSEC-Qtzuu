<?php

/**
 * pfSense CE 2.9.0-DEVELOPMENT limiter hidden-number gadget.
 * Pin 9363ac5b8651a1c7a333180425ce7719070f95f9. Priv page-firewall-trafficshaper-limiter.
 */

$mwexec_log = array();
$dummynet_pipe_list = array();
$g = array('tmp_path' => '/lab/tmp');

putenv('PATH=/lab/bin:' . (getenv('PATH') ?: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'));
ini_set('display_errors', '0');

const WITNESS = 'PFSENSE-LIMITER-NUMBER-WITNESS';
const WITNESS_PATH = '/oracle/PFSENSE-LIMITER-NUMBER-WITNESS';
const PIN_SHA = '9363ac5b8651a1c7a333180425ce7719070f95f9';
const PIN_VERSION = '2.9.0-DEVELOPMENT';

function cleanup_dnqueue_from_rules($qname) {
}

function shaper_dn_config_del($link) {
}

function rename_dnqueue_in_rules($old, $new) {
}

function dummynet_load_module($max_qlimit) {
}

/* util.inc mwexec foreground exec of the concatenated string. */
function mwexec($command, $nologentry = false, $clearsigmask = false, $background = false) {
	global $mwexec_log;
	$retval = 0;
	$mwexec_log[] = $command;
	if ($background) {
		$retval = exec("/usr/bin/nohup $command > /dev/null 2>&1 & echo $!");
	} else {
		$outputarray = array();
		exec("$command 2>&1", $outputarray, $retval);
	}
	return $retval;
}

class dummynet_class {
	var $qname;
	var $qnumber;
	var $link;
	var $subqueues = array();

	function SetLink($link) {
		$this->link = $link;
	}
	function GetLink() {
		return $this->link;
	}
	function GetQname() {
		return $this->qname;
	}
	function SetQname($name) {
		$this->qname = trim($name);
	}
	function SetNumber($number) {
		$this->qnumber = $number;
	}
	function GetNumber() {
		return $this->qnumber;
	}
}

class dnpipe_class extends dummynet_class {
	var $subqueues = array();

	function delete_queue() {
		cleanup_dnqueue_from_rules($this->GetQname());
		foreach ($this->subqueues as $q) {
			$q->delete_queue();
		}
		shaper_dn_config_del($this->GetLink());
		mwexec("/sbin/dnctl pipe delete " . $this->GetNumber());
		mwexec("/sbin/dnctl sched delete " . $this->GetNumber());
	}

	function ReadConfig(&$q) {
		if (!empty($q['name']) && !empty($q['newname']) && $q['name'] != $q['newname']) {
			$this->SetQname($q['newname']);
			rename_dnqueue_in_rules($q['name'], $q['newname']);
		} else if (!empty($q['newname'])) {
			$this->SetQname($q['newname']);
		} else {
			$this->SetQname($q['name']);
		}
		$this->SetNumber($q['number']);
	}

	function wconfig() {
		$cflink = array();
		$cflink['name'] = $this->GetQname();
		$cflink['number'] = $this->GetNumber();
		return $cflink;
	}
}

function dnpipe_find_nextnumber() {
	global $dummynet_pipe_list;

	$dnused = array();
	foreach ($dummynet_pipe_list as $dn) {
		$dnused[] = $dn->GetNumber();
	}

	sort($dnused, SORT_NUMERIC);
	$dnnumber = 0;
	$found = false;
	foreach ($dnused as $dnnum) {
		if (($dnnum - $dnnumber) > 1) {
			$dnnumber = $dnnum - 1;
			$found = true;
			break;
		} else {
			$dnnumber = $dnnum;
		}
	}

	if ($found == false) {
		$dnnumber++;
	}

	unset($dnused, $dnnum, $found);
	return $dnnumber;
}

function reset_oracle() {
	global $mwexec_log;
	$mwexec_log = array();
	if (is_file(WITNESS_PATH)) {
		unlink(WITNESS_PATH);
	}
}

function witness_state() {
	$exists = is_file(WITNESS_PATH);
	$body = '';
	if ($exists) {
		$read = file_get_contents(WITNESS_PATH);
		$body = ($read === false) ? '' : $read;
	}
	return array(
		'exists' => $exists,
		'body' => $body,
		'path' => WITNESS_PATH,
	);
}

function send_json($status, $payload) {
	http_response_code($status);
	header('Content-Type: application/json; charset=utf-8');
	echo json_encode($payload, JSON_UNESCAPED_SLASHES);
	exit(0);
}

function send_text($status, $body) {
	http_response_code($status);
	header('Content-Type: text/plain; charset=utf-8');
	echo $body;
	exit(0);
}

function request_json() {
	static $decoded = null;
	static $read = false;
	if ($read) {
		return is_array($decoded) ? $decoded : array();
	}
	$read = true;
	$raw = file_get_contents('php://input');
	if (!is_string($raw) || $raw === '') {
		$decoded = array();
		return $decoded;
	}
	$parsed = json_decode($raw, true);
	$decoded = is_array($parsed) ? $parsed : array();
	return $decoded;
}

function request_number() {
	if (isset($_POST['number']) && is_string($_POST['number'])) {
		return $_POST['number'];
	}
	$body = request_json();
	if (isset($body['number']) && is_string($body['number'])) {
		return $body['number'];
	}
	return '';
}

function request_case() {
	if (isset($_POST['case']) && is_string($_POST['case'])) {
		return $_POST['case'];
	}
	if (isset($_GET['case']) && is_string($_GET['case'])) {
		return $_GET['case'];
	}
	$body = request_json();
	if (isset($body['case']) && is_string($body['case'])) {
		return $body['case'];
	}
	return '';
}

function run_create($number) {
	global $mwexec_log, $g;
	reset_oracle();
	$pipe = new dnpipe_class();
	$q = array('name' => 'labpipe', 'number' => $number);
	$pipe->ReadConfig($q);
	$before = $pipe->GetNumber();
	$next = dnpipe_find_nextnumber();
	$pipe->SetNumber($next);
	$stored = $pipe->wconfig();
	$pipe->delete_queue();
	return array(
		'case' => 'create',
		'number_posted' => $number,
		'number_before' => $before,
		'number_after' => $pipe->GetNumber(),
		'wconfig_number' => $stored['number'],
		'mwexec' => $mwexec_log,
		'apply_argv' => null,
		'file_body' => null,
		'tmp_path' => $g['tmp_path'],
		'witness' => witness_state(),
	);
}

function run_apply($number) {
	global $mwexec_log, $g;
	reset_oracle();
	$pipe = new dnpipe_class();
	$q = array('name' => 'labpipe', 'number' => $number);
	$pipe->ReadConfig($q);
	$dn_rules = 'pipe ' . $pipe->GetNumber() . " bw 100Kbit/s\n";
	file_put_contents("{$g['tmp_path']}/rules.limiter", $dn_rules);
	mwexec("/sbin/dnctl {$g['tmp_path']}/rules.limiter");
	return array(
		'case' => 'apply',
		'number_posted' => $number,
		'number_after' => $pipe->GetNumber(),
		'mwexec' => $mwexec_log,
		'apply_argv' => "/sbin/dnctl {$g['tmp_path']}/rules.limiter",
		'file_body' => $dn_rules,
		'tmp_path' => $g['tmp_path'],
		'witness' => witness_state(),
	);
}

function run_edit_delete($number) {
	global $mwexec_log, $g;
	reset_oracle();
	$pipe = new dnpipe_class();
	$q = array('name' => 'labpipe', 'number' => $number);
	$pipe->ReadConfig($q);
	$stored = $pipe->wconfig();
	$pipe->delete_queue();
	return array(
		'case' => 'edit-delete',
		'number_posted' => $number,
		'number_after' => $pipe->GetNumber(),
		'wconfig_number' => $stored['number'],
		'mwexec' => $mwexec_log,
		'apply_argv' => null,
		'file_body' => null,
		'tmp_path' => $g['tmp_path'],
		'witness' => witness_state(),
	);
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
	$path = '/';
}

if ($path === '/ping') {
	$which = trim((string) shell_exec('command -v w'));
	send_json(200, array(
		'ok' => true,
		'pong' => 'pong',
		'version' => PIN_VERSION,
		'sha' => PIN_SHA,
		'privilege' => 'page-firewall-trafficshaper-limiter',
		'exec' => function_exists('exec'),
		'which_w' => $which,
		'witness_path' => WITNESS_PATH,
	));
}

if ($path === '/source') {
	$src = file_get_contents(__FILE__);
	if ($src === false) {
		send_text(500, 'source-read-failed');
	}
	send_text(200, $src);
}

if ($path === '/oracle') {
	send_json(200, witness_state());
}

if ($path === '/run') {
	$case = request_case();
	$number = request_number();
	if ($number === '') {
		send_json(400, array('error' => 'missing-number'));
	}
	if ($case === 'create') {
		send_json(200, run_create($number));
	}
	if ($case === 'apply') {
		send_json(200, run_apply($number));
	}
	if ($case === 'edit-delete') {
		send_json(200, run_edit_delete($number));
	}
	send_json(400, array('error' => 'bad-case', 'case' => $case));
}

send_json(404, array('error' => 'not-found', 'path' => $path));
