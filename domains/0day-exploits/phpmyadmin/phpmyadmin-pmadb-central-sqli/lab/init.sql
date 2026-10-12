CREATE DATABASE IF NOT EXISTS `appdb`
  DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE DATABASE IF NOT EXISTS `phpmyadmin`
  DEFAULT CHARACTER SET utf8 COLLATE utf8_bin;

CREATE USER IF NOT EXISTS 'appuser'@'%' IDENTIFIED BY 'apppass';
GRANT ALL PRIVILEGES ON `appdb`.* TO 'appuser'@'%';

CREATE USER IF NOT EXISTS 'pma'@'%' IDENTIFIED BY 'pmapass';
GRANT SELECT, INSERT, UPDATE, DELETE ON `phpmyadmin`.* TO 'pma'@'%';

USE `appdb`;
CREATE TABLE IF NOT EXISTS `lab_table` (
  `id` int NOT NULL,
  PRIMARY KEY (`id`)
);

USE `phpmyadmin`;
CREATE TABLE IF NOT EXISTS `pma__central_columns` (
  `db_name` varchar(64) NOT NULL,
  `col_name` varchar(64) NOT NULL,
  `col_type` varchar(64) NOT NULL,
  `col_length` text,
  `col_collation` varchar(64) NOT NULL,
  `col_isNull` boolean NOT NULL,
  `col_extra` varchar(255) default '',
  `col_default` text,
  PRIMARY KEY (`db_name`, `col_name`)
) COMMENT='Central list of columns'
  DEFAULT CHARACTER SET utf8 COLLATE utf8_bin;

INSERT INTO `pma__central_columns`
  (`db_name`, `col_name`, `col_type`, `col_length`, `col_collation`, `col_isNull`, `col_extra`, `col_default`)
VALUES
  ('appdb', 'seedcol', 'int', '11', '', 0, '', '')
ON DUPLICATE KEY UPDATE `col_type` = VALUES(`col_type`);

FLUSH PRIVILEGES;
