<?php
// Seed one course, an enrolled student, a visible manual item, and a hidden item.
define('CLI_SCRIPT', true);

$config = '/var/www/html/config.php';
if (!is_readable($config)) {
    fwrite(STDERR, "missing config.php\n");
    exit(1);
}

require $config;
require_once $CFG->dirroot . '/course/lib.php';
require_once $CFG->dirroot . '/user/lib.php';
require_once $CFG->libdir . '/gradelib.php';
require_once $CFG->libdir . '/enrollib.php';
require_once $CFG->libdir . '/accesslib.php';

const WITNESS = 'MOODLE-GRADES-GRADEITEMS-WITNESS';
const STUDENT_USER = 'labstudent';
const STUDENT_PASS = 'LabStudentPass1!';
const OUTSIDER_USER = 'laboutsider';
const OUTSIDER_PASS = 'LabOutsiderPass1!';
const COURSE_SHORT = 'labgrades';
const VISIBLE_NAME = 'Visible Lab Assignment';
const HIDDEN_NAME = WITNESS;

global $DB, $CFG;

$release = $CFG->release ?? '';
if (strpos($release, '5.2.3') === false) {
    fwrite(STDERR, "unexpected-release {$release}\n");
    exit(1);
}

set_config('noemailever', 1);
set_config('passwordpolicy', 0);

$make_user = static function (string $username, string $password, string $email): int {
    global $DB, $CFG;
    $existing = $DB->get_record('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id]);
    if ($existing) {
        return (int) $existing->id;
    }
    $user = (object) [
        'auth' => 'manual',
        'username' => $username,
        'password' => $password,
        'firstname' => 'Lab',
        'lastname' => $username,
        'email' => $email,
        'confirmed' => 1,
        'deleted' => 0,
        'suspended' => 0,
        'mnethostid' => $CFG->mnet_localhost_id,
        'lang' => 'en',
        'calendartype' => 'gregorian',
        'mailformat' => 1,
        'maildisplay' => 0,
        'timezone' => 99,
    ];
    $userid = user_create_user($user, true, false);
    $DB->delete_records('user_preferences', [
        'userid' => $userid,
        'name' => 'auth_forcepasswordchange',
    ]);
    return (int) $userid;
};

$studentid = $make_user(STUDENT_USER, STUDENT_PASS, 'labstudent@example.com');
$outsiderid = $make_user(OUTSIDER_USER, OUTSIDER_PASS, 'laboutsider@example.com');

$course = $DB->get_record('course', ['shortname' => COURSE_SHORT]);
if (!$course) {
    $course = create_course((object) [
        'fullname' => 'Grade catalogue lab',
        'shortname' => COURSE_SHORT,
        'category' => 1,
        'visible' => 1,
        'showgrades' => 1,
        'enablecompletion' => 0,
    ]);
}
$courseid = (int) $course->id;
$context = context_course::instance($courseid);

$studentrole = $DB->get_record('role', ['shortname' => 'student'], '*', MUST_EXIST);
$plugin = enrol_get_plugin('manual');
if ($plugin === null) {
    fwrite(STDERR, "manual-enrol-missing\n");
    exit(1);
}
$instance = $DB->get_record('enrol', ['courseid' => $courseid, 'enrol' => 'manual'], '*', IGNORE_MISSING);
if (!$instance) {
    $instanceid = $plugin->add_instance($course);
    $instance = $DB->get_record('enrol', ['id' => $instanceid], '*', MUST_EXIST);
}
$plugin->enrol_user($instance, $studentid, (int) $studentrole->id);

$ensure_item = static function (int $courseid, string $name, bool $hidden): int {
    $items = grade_item::fetch_all(['courseid' => $courseid, 'itemtype' => 'manual', 'itemname' => $name]);
    if ($items) {
        $item = reset($items);
        if ($hidden) {
            $item->set_hidden(1, false);
        } else {
            $item->set_hidden(0, false);
        }
        return (int) $item->id;
    }
    $item = new grade_item();
    $item->courseid = $courseid;
    $item->itemtype = 'manual';
    $item->itemname = $name;
    $item->gradetype = GRADE_TYPE_VALUE;
    $item->grademax = 100;
    $item->grademin = 0;
    $item->insert();
    if ($hidden) {
        $item->set_hidden(1, false);
    }
    return (int) $item->id;
};

$visibleid = $ensure_item($courseid, VISIBLE_NAME, false);
$hiddenid = $ensure_item($courseid, HIDDEN_NAME, true);

$studenthasviewall = has_capability('moodle/grade:viewall', $context, $studentid);
$studenthasviewhidden = has_capability('moodle/grade:viewhidden', $context, $studentid);
if ($studenthasviewall || $studenthasviewhidden) {
    fwrite(STDERR, "student-has-grade-caps viewall=" . (int) $studenthasviewall .
        " viewhidden=" . (int) $studenthasviewhidden . "\n");
    exit(1);
}

$oracle = [
    'release' => $release,
    'courseid' => $courseid,
    'studentid' => $studentid,
    'outsiderid' => $outsiderid,
    'visible_itemid' => $visibleid,
    'hidden_itemid' => $hiddenid,
    'visible_name' => VISIBLE_NAME,
    'hidden_name' => HIDDEN_NAME,
    'student_user' => STUDENT_USER,
    'outsider_user' => OUTSIDER_USER,
    'witness' => WITNESS,
];
$path = $CFG->dataroot . '/lab-oracle.json';
if (file_put_contents($path, json_encode($oracle, JSON_PRETTY_PRINT) . "\n") === false) {
    fwrite(STDERR, "oracle-write-failed\n");
    exit(1);
}
@chmod($path, 0644);

fwrite(STDOUT, "seed-ok courseid={$courseid} hiddenid={$hiddenid} visibleid={$visibleid}\n");
exit(0);
