-- pmadb designer_settings only. appuser has no GRANT on phpmyadmin.
CREATE DATABASE IF NOT EXISTS `phpmyadmin`
  DEFAULT CHARACTER SET utf8 COLLATE utf8_bin;
CREATE DATABASE IF NOT EXISTS `appdb`;

USE phpmyadmin;

CREATE TABLE IF NOT EXISTS `pma__designer_settings` (
  `username` varchar(64) NOT NULL,
  `settings_data` text NOT NULL,
  PRIMARY KEY (`username`)
) DEFAULT CHARACTER SET utf8 COLLATE utf8_bin
  COMMENT='Settings related to Designer';

INSERT INTO `pma__designer_settings` (`username`, `settings_data`) VALUES
  ('victim', '{"keep":"safe"}')
ON DUPLICATE KEY UPDATE `settings_data` = VALUES(`settings_data`);

CREATE USER IF NOT EXISTS 'pma'@'%' IDENTIFIED BY 'pmapass';
GRANT SELECT, INSERT, UPDATE, DELETE ON `phpmyadmin`.* TO 'pma'@'%';

USE appdb;
CREATE TABLE IF NOT EXISTS `t` (
  `id` int NOT NULL,
  PRIMARY KEY (`id`)
);

FLUSH PRIVILEGES;
