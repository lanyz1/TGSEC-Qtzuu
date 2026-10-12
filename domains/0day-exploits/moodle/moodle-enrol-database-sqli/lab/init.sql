USE enrol_ext;

CREATE TABLE IF NOT EXISTS enrolments (
  courseid VARCHAR(255) NOT NULL,
  userid VARCHAR(255) NOT NULL,
  role VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

INSERT INTO enrolments (courseid, userid, role) VALUES
  ('LABCOURSE', 'teacher-local', 'editingteacher'),
  ('SECRET', 'MOODLE-ENROL-DATABASE-SQLI-WITNESS', 'manager');
