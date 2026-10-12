-- pmadb userconfig only. 2FA is enrolled through Settings, not this seed.
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
FLUSH PRIVILEGES;
