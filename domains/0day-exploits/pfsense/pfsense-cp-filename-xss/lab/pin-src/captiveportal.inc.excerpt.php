<?php
/* Pin excerpt pfsense/pfsense 9363ac5b8651a1c7a333180425ce7719070f95f9. Do not edit by hand. */

function get_captive_portal_logo() {
	global $g, $cpzone;
	$logo_src = "captiveportal-default-logo.png";
	// Check if customlogo is set and if the element exists
	// Check if the image is in the directory
	$cpzone_config = config_get_path("captiveportal/{$cpzone}", []);
	if (isset($cpzone_config['customlogo']) &&
	    is_array($cpzone_config['element']) &&
	    !empty($cpzone_config['element'])) {
		foreach ($cpzone_config['element'] as $element) {
			if (strpos($element['name'], "captiveportal-logo.") !== false) {
				if (file_exists("{$g['captiveportal_path']}/{$element['name']}")) {
					$logo_src = $element['name'];
					break;
				}
			}
		}
	}
	return $logo_src;
}

function get_captive_portal_bg() {
	$bg_src = "linear-gradient(135deg, #1475CF, #2B40B5, #1C1275)";
	global $g, $cpzone;
	// check if custombg is set and if the element exists
	$cpzone_config = config_get_path("captiveportal/{$cpzone}", []);
	if (isset($cpzone_config['custombg']) &&
	    is_array($cpzone_config['element']) &&
	    !empty($cpzone_config['element'])) {
		foreach ($cpzone_config['element'] as $element) {
			if (strpos($element['name'],"captiveportal-background.") !== false) {
				if( file_exists("{$g['captiveportal_path']}/{$element['name']}")) {
					$bg_src = "url(" . $element['name'] . ")" . "center center no-repeat fixed";
					break;
				}
			}
		}
	}
	return $bg_src;
}

function get_default_captive_portal_html() {
	global $g, $cpzone;

	$translated_text1 = gettext("User");
	$translated_text2 = gettext("Password");
	$translated_text3 = gettext("First Authentication Method ");
	$translated_text4 = gettext("Second Authentication Method ");
	// default images to use.
	$logo_src = get_captive_portal_logo();
	$bg_src = get_captive_portal_bg();
	// bring in terms and conditions
	$cpzone_config = config_get_path("captiveportal/{$cpzone}", []);
	$termsconditions = base64_decode($cpzone_config['termsconditions']);
	// if there is no terms and conditions do not require the checkbox to be selected.
	$disabled = "";
	if ($termsconditions) {
		$disabled = "disabled";
	}
	$htmltext = <<<EOD
<!DOCTYPE html>
<html>

<head>

  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
  <title>Captive Portal Login Page</title>
  <style>
	  #content,.login,.login-card a,.login-card h1,.login-help{text-align:center}body,html{margin:0;padding:0;width:100%;height:100%;display:table}#content{font-family:'Source Sans Pro',sans-serif;background-color:#1C1275;background:{$bg_src};-webkit-background-size:cover;-moz-background-size:cover;-o-background-size:cover;background-size:cover;display:table-cell;vertical-align:middle}.login-card{padding:40px;width:280px;background-color:#F7F7F7;margin:100px auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}.login-card h1{font-weight:400;font-size:2.3em;color:#1383c6}.login-card h1 span{color:#f26721}.login-card img{width:70%;height:70%}.login-card input[type=submit]{width:100%;display:block;margin-bottom:10px;position:relative}.login-card input[type=text],input[type=password]{height:44px;font-size:16px;width:100%;margin-bottom:10px;-webkit-appearance:none;background:#fff;border:1px solid #d9d9d9;border-top:1px solid silver;padding:0 8px;box-sizing:border-box;-moz-box-sizing:border-box}.login-card input[type=text]:hover,input[type=password]:hover{border:1px solid #b9b9b9;border-top:1px solid #a0a0a0;-moz-box-shadow:inset 0 1px 2px rgba(0,0,0,.1);-webkit-box-shadow:inset 0 1px 2px rgba(0,0,0,.1);box-shadow:inset 0 1px 2px rgba(0,0,0,.1)}.login{font-size:14px;font-family:Arial,sans-serif;font-weight:700;height:36px;padding:0 8px}.login-submit{-webkit-appearance:none;-moz-appearance:none;appearance:none;border:0;color:#fff;text-shadow:0 1px rgba(0,0,0,.1);background-color:#4d90fe}.login-submit:disabled{opacity:.6}.login-submit:hover{border:0;text-shadow:0 1px rgba(0,0,0,.3);background-color:#357ae8}.login-card a{text-decoration:none;color:#222;font-weight:400;display:inline-block;opacity:.6;transition:opacity ease .5s}.login-card a:hover{opacity:1}.login-help{width:100%;font-size:12px}.list{list-style-type:none;padding:0}.list__item{margin:0 0 .7rem;padding:0}label{display:-webkit-box;display:-webkit-flex;display:-ms-flexbox;display:flex;-webkit-box-align:center;-webkit-align-items:center;-ms-flex-align:center;align-items:center;text-align:left;font-size:14px;}input[type=checkbox]{-webkit-box-flex:0;-webkit-flex:none;-ms-flex:none;flex:none;margin-right:10px;float:left}@media screen and (max-width:450px){.login-card{width:70%!important}.login-card img{width:30%;height:30%}}textarea{width:66%;margin:auto;height:120px;max-height:120px;background-color:#f7f7f7;padding:20px}#terms{display:none;padding-top:100px;padding-bottom:300px;}.auth_source{border: 1px solid lightgray; padding:20px 8px 0px 8px; margin-top: -2em; border-radius: 2px; }.auth_head{background-color:#f7f7f7;display:inline-block;}.auth_head_div{text-align:left;}#error-message{text-align:left;color:#ff3e3e;font-style:italic;}
  </style>
</head>

<body>
<div id="content">
	<div class="login-card">
		<img src="{$logo_src}"/><br>
 		<h1></h1>
		<div id="error-message">
			\$PORTAL_MESSAGE\$
		</div>
	  <form name="login_form" method="post" action="\$PORTAL_ACTION\$">
EOD;
	if ($cpzone_config['auth_method'] != "none"){
		if ($cpzone_config['auth_method'] === 'authserver' && !empty($cpzone_config['auth_server2'])) {
			$htmltext .= <<<EOD
			<div class="auth_head_div">
				<h6 class="auth_head">{$translated_text3}</h6>
			</div>
			<div class="auth_source">

EOD;
		}
		$htmltext .=<<<EOD
		<input type="text" name="auth_user" placeholder="{$translated_text1}" id="auth_user">
		<input type="password" name="auth_pass" placeholder="{$translated_text2}" id="auth_pass">
EOD;

		if ($cpzone_config['auth_method'] === 'authserver' && !empty($cpzone_config['auth_server2'])) {
			$htmltext .= <<<EOD
			</div>
			<div class="auth_head_div">
				<h6 class="auth_head">{$translated_text4}</h6>
			</div>
			<div class="auth_source">

			<input type="text" name="auth_user2" placeholder="{$translated_text1}" id="auth_user2">
			<input type="password" name="auth_pass2" placeholder="{$translated_text2}" id="auth_pass2">
			</div>
EOD;
		}


		if (config_path_enabled("voucher/{$cpzone}")) {
			$translated_text = gettext("Voucher Code");
			$htmltext .= <<<EOD
				<br  /><br  />
				<input name="auth_voucher" type="text" placeholder="{$translated_text}" value="#VOUCHER#">
EOD;
		}
	}

if ($termsconditions) {
	$htmltext .= <<<EOD
		  <div class="login-help">
			<ul class="list">
				<li class="list__item">
				  <label class="label--checkbox">
					<input type="checkbox" class="checkbox" onchange="document.getElementById('login').disabled = !this.checked;">
					<span>I agree with the <a  rel="noopener" href="#terms" onclick="document.getElementById('terms').style.display = 'block';">terms & conditions</a></span>
				  </label>
				</li>
			</ul>
		  </div>
EOD;
}
	$htmltext .= <<<EOD

		<input name="redirurl" type="hidden" value="\$PORTAL_REDIRURL\$">
		<input type="submit" name="accept" class="login login-submit" value="Login" id="login" {$disabled}>
	  </form>
	  <br  />
	  <span> <i>Made with &hearts; by</i> <strong>Netgate</strong></span>
	</div>
	<div id="terms">
		<textarea readonly>{$termsconditions}</textarea>
	</div>
</div>
</body>
</html>

EOD;

	return $htmltext;
}
