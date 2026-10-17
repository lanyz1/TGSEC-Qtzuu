<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

class updatedns {
	var $_cacheFile;
	var $_cacheFile_v6;
	var $_debugFile;
	var $_FQDN;
	var $_dnsService;
	var $_dnsHost;
	var $_dnsResultMatch;
	var $_dnsIP;
	var $_if;
	var $_dnsID;
	var $_addressFamilyRR;
	var $status = '';

	/*
	 * Public Constructor Function (added 12 July 05) [beta]
	 *   - Gets the dice rolling for the update.
	 *   - $dnsResultMatch should only be used with $dnsService = 'custom'
	 */
	function __construct($dnsService = '', $dnsHost = '', $dnsDomain = '', $dnsUser = '', $dnsPass = '',
					$dnsWildcard = 'OFF', $dnsProxied = false, $dnsMX = '', $dnsIf = '', $dnsBackMX = '',
					$dnsServer = '', $dnsPort = '', $dnsUpdateURL = '', $forceUpdate = false,
					$dnsZoneID ='', $dnsTTL='', $dnsResultMatch = '', $dnsRequestIf = '', $dnsMaxCacheAge = '',
					$dnsID = '', $dnsVerboseLog = false, $curlIpresolveV4 = false, $curlSslVerifypeer = true,
					$curlProxy = false, $checkIPMode = null) {

		global $g, $dyndns_split_domain_types;
		if (in_array($dnsService, $dyndns_split_domain_types)) {
			$this->_FQDN = $dnsHost . "." . $dnsDomain;
		} else {
			$this->_FQDN = $dnsHost;
		}

		$this->_cacheFile = "{$g['conf_path']}/dyndns_{$dnsIf}{$dnsService}" . escapeshellarg($this->_FQDN) . "{$dnsID}.cache";
		$this->_cacheFile_v6 = "{$g['conf_path']}/dyndns_{$dnsIf}{$dnsService}" . escapeshellarg($this->_FQDN) . "{$dnsID}_v6.cache";
		$this->_debugFile = "{$g['varetc_path']}/dyndns_{$dnsIf}{$dnsService}" . escapeshellarg($this->_FQDN) . "{$dnsID}.debug";

		$this->_dnsService = $dnsService;
		$this->_dnsHost = $dnsHost;
		$this->_dnsResultMatch = $dnsResultMatch;
		$this->_if = $dnsIf;
		$this->_dnsID = $dnsID;
		$this->_addressFamilyRR = AF_INET;
		/* Lab: skip provider curl. Cache write is the leftover. */
	}

	function lab_commit_ipv4($ip) {
		$this->_dnsIP = $ip;
		$successful_update = false;
		$data = '';
		$status_intro = '';
		$success_str = '';
		$error_str = '';
		$status = '';
		switch ($this->_dnsService) {
			// The special custom provider
			case 'custom':
			case 'custom-v6':
				$successful_update = false;
				if ($this->_dnsResultMatch == "") {
					$successful_update = true;
				} else {
					$this->_dnsResultMatch = str_replace("%IP%", $this->_dnsIP, $this->_dnsResultMatch);
					$matches = preg_split("/(?<!\\\\)\\|/", $this->_dnsResultMatch);
					foreach ($matches as $match) {
						$match= str_replace("\\|", "|", $match);
						if (strcmp($match, trim($data, "\t\n\r")) == 0) {
							$successful_update = true;
						}
					}
					unset ($matches);
				}
				if ($successful_update == true) {
					$status = $status_intro . $success_str . gettext("IP Address Updated Successfully!");
				} else {
					$status = $status_intro . $error_str . gettext("Result did not match.") . " [" . $data . "]";
				}
				break;
			default:
				break;
		}

		if ($successful_update == true) {
			/* Write WAN IP to cache file */
			if ($this->_addressFamilyRR == AF_INET) {
				$currentTime = time();
				notify_all_remote(sprintf(gettext('DynDNS updated IP Address for %1$s on %2$s (%3$s) to %4$s'), $this->_FQDN, convert_real_interface_to_friendly_descr($this->_if), $this->_if, $this->_dnsIP));
				logger(LOG_INFO, localize_text('updating cache file %1$s: %2$s', $this->_cacheFile, $this->_dnsIP), LOG_PREFIX_DDNS);
				@file_put_contents($this->_cacheFile, "{$this->_dnsIP}|{$currentTime}");
			} else {
				@unlink($this->_cacheFile);
			}
			if ($this->_addressFamilyRR == AF_INET6) {
				$currentTime = time();
				notify_all_remote(sprintf(gettext('DynDNS updated IPv6 Address for %1$s on %2$s (%3$s) to %4$s'), $this->_FQDN, convert_real_interface_to_friendly_descr($this->_if), $this->_if, $this->_dnsIP));
				logger(LOG_INFO, localize_text('updating cache file %1$s: %2$s', $this->_cacheFile_v6, $this->_dnsIP), LOG_PREFIX_DDNS);
				@file_put_contents($this->_cacheFile_v6, "{$this->_dnsIP}|{$currentTime}");
			} else {
				@unlink($this->_cacheFile_v6);
			}
		}
		$this->status = $status;
		logger(LOG_INFO, $status, LOG_PREFIX_DDNS);
		return $successful_update;
	}
}
