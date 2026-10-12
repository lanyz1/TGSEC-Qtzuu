<?php
unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mariadb';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'db';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'moodle';
$CFG->dbpass    = 'LabDbPassw0rd!';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = [
    'dbpersist' => false,
    'dbsocket'  => false,
    'dbport'    => 3306,
    'dbhandlesoptions' => false,
    'dbcollation' => 'utf8mb4_unicode_ci',
];

$CFG->wwwroot   = 'http://127.0.0.1:19580';
$CFG->dataroot  = '/var/www/moodledata';
$CFG->admin     = 'admin';
$CFG->directorypermissions = 02777;
$CFG->noemailever = true;
$CFG->debugdisplay = 0;
// Host maps 19580->80; Moodle compares SERVER_PORT to wwwroot unless reverseproxy is on.
$CFG->reverseproxy = true;

require_once(__DIR__ . '/lib/setup.php');
