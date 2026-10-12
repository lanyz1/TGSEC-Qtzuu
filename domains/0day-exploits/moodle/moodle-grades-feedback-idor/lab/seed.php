<?php
define('CLI_SCRIPT', true);
define('NO_OUTPUT_BUFFERING', true);

require '/var/www/html/config.php';
require_once $CFG->dirroot . '/user/lib.php';
require_once $CFG->dirroot . '/course/lib.php';
require_once $CFG->libdir . '/enrollib.php';
require_once $CFG->dirroot . '/group/lib.php';
require_once $CFG->libdir . '/gradelib.php';
require_once $CFG->libdir . '/accesslib.php';

global $CFG, $DB;

\core\cron::setup_user();
set_config('passwordpolicy', 0);

$witness = getenv('WITNESS') ?: 'MOODLE-GRADES-FEEDBACK-IDOR-WITNESS';
$teacheruser = 'teachera';
$studenta = 'studenta';
$studentb = 'studentb';
$password = 'TeacherPass1!';
$studentpass = 'StudentPass1!';

$release = (string) $CFG->release;
$pinok = str_contains($release, '5.2.3');
$feedbacksrc = file_get_contents($CFG->dirroot . '/grade/classes/external/get_feedback.php');
$hascap = str_contains($feedbacksrc, "require_capability('gradereport/grader:view'");
$hasgroup = str_contains($feedbacksrc, 'groups_user_groups_visible');

$existing = $DB->get_record('user', ['username' => $teacheruser, 'deleted' => 0], '*', IGNORE_MISSING);
if ($existing) {
    $course = $DB->get_record('course', ['shortname' => 'fbidor'], '*', MUST_EXIST);
    $teacher = $existing;
    $user_a = $DB->get_record('user', ['username' => $studenta], '*', MUST_EXIST);
    $user_b = $DB->get_record('user', ['username' => $studentb], '*', MUST_EXIST);
    $group_a = $DB->get_record('groups', ['courseid' => $course->id, 'name' => 'Group A'], '*', MUST_EXIST);
    $group_b = $DB->get_record('groups', ['courseid' => $course->id, 'name' => 'Group B'], '*', MUST_EXIST);
    $item = $DB->get_record('grade_items', ['courseid' => $course->id, 'itemname' => 'Lab feedback item'], '*', MUST_EXIST);
} else {
    $course = create_course((object) [
        'fullname' => 'Feedback IDOR Lab',
        'shortname' => 'fbidor',
        'category' => 1,
        'visible' => 1,
        'startdate' => time() - 86400,
        'enddate' => 0,
        'groupmode' => SEPARATEGROUPS,
        'groupmodeforce' => 1,
    ]);

    $mkuser = static function (string $username, string $email, string $first, string $last, string $pass): int {
        global $CFG;
        $user = (object) [
            'auth' => 'manual',
            'username' => $username,
            'password' => $pass,
            'firstname' => $first,
            'lastname' => $last,
            'email' => $email,
            'confirmed' => 1,
            'policyagreed' => 1,
            'mnethostid' => $CFG->mnet_localhost_id,
            'lang' => 'en',
            'calendartype' => 'gregorian',
        ];
        return (int) user_create_user($user, true, false);
    };

    $teacherid = $mkuser($teacheruser, 'teachera@example.com', 'Teacher', 'Alpha', $password);
    $aid = $mkuser($studenta, 'studenta@example.com', 'Student', 'Alpha', $studentpass);
    $bid = $mkuser($studentb, 'studentb@example.com', 'Student', 'Bravo', $studentpass);

    $plugin = enrol_get_plugin('manual');
    if ($plugin === null) {
        fwrite(STDERR, "manual enrol plugin missing\n");
        exit(1);
    }
    $manual = null;
    foreach (enrol_get_instances($course->id, true) as $inst) {
        if ($inst->enrol === 'manual') {
            $manual = $inst;
            break;
        }
    }
    if ($manual === null) {
        $instanceid = $plugin->add_default_instance($course);
        if (!$instanceid) {
            $instanceid = $plugin->add_instance($course);
        }
        $manual = $DB->get_record('enrol', ['id' => $instanceid], '*', MUST_EXIST);
    }

    $teacherrole = $DB->get_record('role', ['shortname' => 'teacher'], '*', MUST_EXIST);
    $studentrole = $DB->get_record('role', ['shortname' => 'student'], '*', MUST_EXIST);
    $plugin->enrol_user($manual, $teacherid, (int) $teacherrole->id);
    $plugin->enrol_user($manual, $aid, (int) $studentrole->id);
    $plugin->enrol_user($manual, $bid, (int) $studentrole->id);

    $context = context_course::instance($course->id);
    role_change_permission(
        (int) $teacherrole->id,
        $context,
        'moodle/site:accessallgroups',
        CAP_PREVENT
    );

    $group_a_id = groups_create_group((object) [
        'courseid' => $course->id,
        'name' => 'Group A',
        'description' => 'Group A',
        'descriptionformat' => FORMAT_PLAIN,
    ]);
    $group_b_id = groups_create_group((object) [
        'courseid' => $course->id,
        'name' => 'Group B',
        'description' => 'Group B',
        'descriptionformat' => FORMAT_PLAIN,
    ]);
    groups_add_member($group_a_id, $teacherid);
    groups_add_member($group_a_id, $aid);
    groups_add_member($group_b_id, $bid);

    $gradeitem = new grade_item([
        'courseid' => $course->id,
        'itemtype' => 'manual',
        'itemname' => 'Lab feedback item',
        'gradetype' => GRADE_TYPE_VALUE,
        'grademax' => 100,
        'grademin' => 0,
    ], false);
    $gradeitem->insert();

    $grade = new grade_grade([
        'itemid' => $gradeitem->id,
        'userid' => $bid,
        'rawgrade' => 88,
        'finalgrade' => 88,
        'feedback' => $witness,
        'feedbackformat' => FORMAT_PLAIN,
    ], false);
    $grade->insert();

    $teacher = $DB->get_record('user', ['id' => $teacherid], '*', MUST_EXIST);
    $user_a = $DB->get_record('user', ['id' => $aid], '*', MUST_EXIST);
    $user_b = $DB->get_record('user', ['id' => $bid], '*', MUST_EXIST);
    $group_a = $DB->get_record('groups', ['id' => $group_a_id], '*', MUST_EXIST);
    $group_b = $DB->get_record('groups', ['id' => $group_b_id], '*', MUST_EXIST);
    $item = $DB->get_record('grade_items', ['id' => $gradeitem->id], '*', MUST_EXIST);
}

$context = context_course::instance($course->id);
$course = $DB->get_record('course', ['id' => $course->id], '*', MUST_EXIST);

$out = [
    'release' => $release,
    'pin_ok' => $pinok,
    'source_has_grader_view' => $hascap,
    'source_has_groups_check' => $hasgroup,
    'courseid' => (int) $course->id,
    'groupmode' => (int) $course->groupmode,
    'groupmodeforce' => (int) $course->groupmodeforce,
    'teacherid' => (int) $teacher->id,
    'teacheruser' => $teacher->username,
    'studentaid' => (int) $user_a->id,
    'studentbid' => (int) $user_b->id,
    'groupaid' => (int) $group_a->id,
    'groupbid' => (int) $group_b->id,
    'itemid' => (int) $item->id,
    'grader_view' => has_capability('gradereport/grader:view', $context, $teacher->id),
    'accessallgroups' => has_capability('moodle/site:accessallgroups', $context, $teacher->id),
    'teacher_in_a' => groups_is_member($group_a->id, $teacher->id),
    'teacher_in_b' => groups_is_member($group_b->id, $teacher->id),
    'studentb_in_b' => groups_is_member($group_b->id, $user_b->id),
    'studentb_in_a' => groups_is_member($group_a->id, $user_b->id),
    'witness' => $witness,
];

echo 'LAB_SEED=' . json_encode($out, JSON_UNESCAPED_SLASHES) . PHP_EOL;
