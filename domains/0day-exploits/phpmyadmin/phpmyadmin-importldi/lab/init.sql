CREATE TABLE IF NOT EXISTS `appdb`.`ldi_target` (
  `id` INT NOT NULL,
  `note` VARCHAR(64) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `appdb`.`ldi_target` (`id`, `note`)
VALUES (1, 'seed')
ON DUPLICATE KEY UPDATE `note` = VALUES(`note`);
