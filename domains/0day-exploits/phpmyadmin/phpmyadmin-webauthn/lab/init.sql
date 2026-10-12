-- Lab seed: pmadb + WebAuthn 2FA enrolled for appuser without a hardware key.
-- Credential id = 32 x 0xA1 (urlsafe AQEBAQ... padded off).

CREATE DATABASE IF NOT EXISTS `phpmyadmin`
  DEFAULT CHARACTER SET utf8 COLLATE utf8_bin;
USE phpmyadmin;

CREATE TABLE IF NOT EXISTS `pma__userconfig` (
  `username` varchar(64) NOT NULL,
  `timevalue` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `config_data` text NOT NULL,
  PRIMARY KEY (`username`)
) DEFAULT CHARACTER SET utf8 COLLATE utf8_bin;

CREATE USER IF NOT EXISTS 'pma'@'%' IDENTIFIED BY 'pmapass';
GRANT SELECT, INSERT, UPDATE, DELETE ON `phpmyadmin`.* TO 'pma'@'%';

-- publicKeyCredentialId is urlsafe-no-pad of 32 0xA1 bytes:
-- python3 -c "import base64; print(base64.urlsafe_b64encode(b'\\xa1'*32).decode().rstrip('='))"
INSERT INTO `pma__userconfig` (`username`, `config_data`) VALUES (
  'appuser',
  '{"2fa":{"backend":"WebAuthn","settings":{"userHandle":"cG1hLWxhYi11c2VyLWhhbmRsZS1vayEh","credentials":{"oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaE=":{"publicKeyCredentialId":"oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaE","type":"public-key","transports":[],"attestationType":"none","credentialPublicKey":"pQECAyYgASFYIBw_HArIcANWNOBOxq3hH8lrHo9a17nQDxlqwybjDpHEIlggu3QUKIbALqsGuHfJI3LTKJSNmk0YCFb5oz1hjJidRMk","userHandle":"cG1hLWxhYi11c2VyLWhhbmRsZS1vayEh","counter":0}}}}}'
) ON DUPLICATE KEY UPDATE `config_data` = VALUES(`config_data`);

FLUSH PRIVILEGES;
