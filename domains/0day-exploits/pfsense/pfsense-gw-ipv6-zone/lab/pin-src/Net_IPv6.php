<?php
/* PEAR Net_IPv6 subset. checkIPv6 accepts fe80::1. getAddressType uses
 * _ip2Bin/base_convert, which drops %zone and trailing non-hex. */

define("NET_IPV6_LOCAL_LINK", 42);
define("NET_IPV6_UNKNOWN_TYPE", 1001);

class Net_IPv6
{
	public static function checkIPv6($ip)
	{
		$elements = self::separate($ip);
		$ip = $elements[0];
		if ('' != $elements[1] && (!is_numeric($elements[1]) || 0 > $elements[1] || 128 < $elements[1])) {
			return false;
		}
		$ipPart = self::SplitV64($ip);
		$count = 0;
		if (!empty($ipPart[0])) {
			$ipv6 = explode(':', $ipPart[0]);
			foreach ($ipv6 as $element) {
				if (!preg_match('/[0-9a-fA-F]*/', $element)) {
					return false;
				}
			}
			for ($i = 0; $i < count($ipv6); $i++) {
				if (4 < strlen($ipv6[$i])) {
					return false;
				}
				$dec = hexdec($ipv6[$i]);
				$hex = strtoupper(preg_replace("/^[0]{1,3}(.*[0-9a-fA-F])$/", "\\1", $ipv6[$i]));
				if ($ipv6[$i] >= 0 && $dec <= 65535 && $hex == strtoupper(dechex($dec))) {
					$count++;
				}
			}
			if (8 == $count) {
				return true;
			}
			return false;
		}
		return false;
	}

	public static function getAddressType($ip)
	{
		$ip = self::removeNetmaskSpec($ip);
		$binip = self::_ip2Bin($ip);
		if (0 == strncmp('1111111010', $binip, 10)) {
			return NET_IPV6_LOCAL_LINK;
		}
		return NET_IPV6_UNKNOWN_TYPE;
	}

	public static function separate($ip)
	{
		$addr = $ip;
		$spec = '';
		if (false === strrpos($ip, '/')) {
			return array($addr, $spec);
		}
		$elements = explode('/', $ip);
		if (2 == count($elements)) {
			$addr = $elements[0];
			$spec = $elements[1];
		}
		return array($addr, $spec);
	}

	public static function removeNetmaskSpec($ip)
	{
		$elements = self::separate($ip);
		return $elements[0];
	}

	public static function getNetmaskSpec($ip)
	{
		$elements = self::separate($ip);
		return $elements[1];
	}

	public static function getPrefixLength($ip)
	{
		if (preg_match("/^([0-9a-fA-F:]{2,39})\/(\d{1,3})*$/", $ip, $matches)) {
			return $matches[2];
		}
		return false;
	}

	public static function removePrefixLength($ip)
	{
		$pos = strrpos($ip, '/');
		if (false !== $pos) {
			return substr($ip, 0, $pos);
		}
		return $ip;
	}

	public static function uncompress($ip, $leadingZeros = false)
	{
		$prefix = self::getPrefixLength($ip);
		if (false === $prefix) {
			$prefix = '';
		} else {
			$ip = self::removePrefixLength($ip);
			$prefix = '/' . $prefix;
		}
		$netmask = self::getNetmaskSpec($ip);
		$uip = self::removeNetmaskSpec($ip);
		$c1 = -1;
		$c2 = -1;
		if (false !== strpos($uip, '::')) {
			list($ip1, $ip2) = explode('::', $uip);
			if ("" == $ip1) {
				$c1 = -1;
			} else {
				$pos = 0;
				if (0 < ($pos = substr_count($ip1, ':'))) {
					$c1 = $pos;
				} else {
					$c1 = 0;
				}
			}
			if ("" == $ip2) {
				$c2 = -1;
			} else {
				$pos = 0;
				if (0 < ($pos = substr_count($ip2, ':'))) {
					$c2 = $pos;
				} else {
					$c2 = 0;
				}
			}
			if (strstr($ip2, '.')) {
				$c2++;
			}
			if (-1 == $c1 && -1 == $c2) {
				$uip = "0:0:0:0:0:0:0:0";
			} else if (-1 == $c1) {
				$fill = str_repeat('0:', 7 - $c2);
				$uip = str_replace('::', $fill, $uip);
			} else if (-1 == $c2) {
				$fill = str_repeat(':0', 7 - $c1);
				$uip = str_replace('::', $fill, $uip);
			} else {
				$fill = str_repeat(':0:', max(1, 6 - $c2 - $c1));
				$uip = str_replace('::', $fill, $uip);
				$uip = str_replace('::', ':', $uip);
			}
		}
		if (true == $leadingZeros) {
			$uipT = array();
			$uiparts = explode(':', $uip);
			foreach ($uiparts as $p) {
				$uipT[] = sprintf('%04s', $p);
			}
			$uip = implode(':', $uipT);
		}
		if ('' != $netmask) {
			$uip = $uip . '/' . $netmask;
		}
		return $uip . $prefix;
	}

	public static function SplitV64($ip, $uncompress = true)
	{
		$ip = self::removeNetmaskSpec($ip);
		if ($uncompress) {
			$ip = self::uncompress($ip);
		}
		if (strstr($ip, '.')) {
			$pos = strrpos($ip, ':');
			$ip[$pos] = '_';
			$ipPart = explode('_', $ip);
			return $ipPart;
		}
		return array($ip, "");
	}

	public static function _ip2Bin($ip)
	{
		$binstr = '';
		$ip = self::removeNetmaskSpec($ip);
		$ip = self::uncompress($ip);
		$parts = explode(':', $ip);
		foreach ($parts as $v) {
			$str = base_convert($v, 16, 2);
			$binstr .= str_pad($str, 16, '0', STR_PAD_LEFT);
		}
		return $binstr;
	}
}
