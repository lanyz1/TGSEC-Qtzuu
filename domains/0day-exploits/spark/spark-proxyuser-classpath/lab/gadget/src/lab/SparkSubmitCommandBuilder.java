package lab;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Stub of pin v4.2.0 SparkSubmitCommandBuilder.java:312-327 plus OptionParser --conf
 * (572-576) and isClientMode (483-488). Cluster mode omits spark.driver.extraClassPath
 * but always appends spark.driver.defaultExtraClassPath onto the spark-submit JVM -cp.
 */
final class SparkSubmitCommandBuilder {

  private SparkSubmitCommandBuilder() {}

  static ParsedSubmit parse(List<String> argv) {
    Map<String, String> conf = new LinkedHashMap<>();
    String master = null;
    String deployMode = null;
    String proxyUser = null;
    String jars = null;
    String primaryResource = null;
    for (int i = 0; i < argv.size(); i++) {
      String opt = argv.get(i);
      switch (opt) {
        case "--master" -> master = argv.get(++i);
        case "--deploy-mode" -> deployMode = argv.get(++i);
        case "--proxy-user" -> proxyUser = argv.get(++i);
        case "--jars" -> jars = argv.get(++i);
        case "--driver-class-path" -> conf.put(SparkLauncher.DRIVER_EXTRA_CLASSPATH, argv.get(++i));
        case "--driver-default-class-path" ->
            conf.put(SparkLauncher.DRIVER_DEFAULT_EXTRA_CLASS_PATH, argv.get(++i));
        case "--conf" -> {
          String value = argv.get(++i);
          String[] setConf = value.split("=", 2);
          if (setConf.length != 2) {
            throw new IllegalArgumentException("Invalid argument to --conf: " + value);
          }
          conf.put(setConf[0], setConf[1]);
        }
        default -> {
          if (!opt.startsWith("-")) {
            primaryResource = opt;
          }
        }
      }
    }
    if (master != null) {
      conf.putIfAbsent(SparkLauncher.SPARK_MASTER, master);
    }
    if (deployMode != null) {
      conf.putIfAbsent(SparkLauncher.DEPLOY_MODE, deployMode);
    }
    conf.putIfAbsent(
        SparkLauncher.DRIVER_DEFAULT_EXTRA_CLASS_PATH,
        SparkLauncher.DRIVER_DEFAULT_EXTRA_CLASS_PATH_VALUE);
    return new ParsedSubmit(conf, master, deployMode, proxyUser, jars, primaryResource);
  }

  static boolean isClientMode(String master, String deployMode, Map<String, String> userProps) {
    String userMaster = firstNonEmpty(master, userProps.get(SparkLauncher.SPARK_MASTER));
    String userDeployMode = firstNonEmpty(deployMode, userProps.get(SparkLauncher.DEPLOY_MODE));
    return userMaster == null || userDeployMode == null || "client".equals(userDeployMode);
  }

  /**
   * Pin SparkSubmitCommandBuilder.java:318-325. extraClassPath is null in cluster mode;
   * defaultExtraClassPath is still concatenated onto the submit JVM -cp.
   */
  static String sparkSubmitExtraClassPath(boolean isClientMode, Map<String, String> config) {
    String extraClassPath = isClientMode ? config.get(SparkLauncher.DRIVER_EXTRA_CLASSPATH) : null;
    String defaultExtraClassPath = config.get(SparkLauncher.DRIVER_DEFAULT_EXTRA_CLASS_PATH);
    if (extraClassPath == null || extraClassPath.trim().isEmpty()) {
      extraClassPath = defaultExtraClassPath;
    } else {
      extraClassPath += File.pathSeparator + defaultExtraClassPath;
    }
    return extraClassPath;
  }

  static List<String> buildClassPath(String appClassPath, String... rest) {
    Set<String> cp = new LinkedHashSet<>();
    addToClassPath(cp, appClassPath);
    for (String entry : rest) {
      addToClassPath(cp, entry);
    }
    return new ArrayList<>(cp);
  }

  private static void addToClassPath(Set<String> cp, String entries) {
    if (isEmpty(entries)) {
      return;
    }
    String[] split = entries.split(Pattern.quote(File.pathSeparator));
    for (String entry : split) {
      if (!isEmpty(entry)) {
        if (new File(entry).isDirectory() && !entry.endsWith(File.separator)) {
          entry += File.separator;
        }
        cp.add(entry);
      }
    }
  }

  private static String firstNonEmpty(String... candidates) {
    for (String value : candidates) {
      if (!isEmpty(value)) {
        return value;
      }
    }
    return null;
  }

  private static boolean isEmpty(String value) {
    return value == null || value.trim().isEmpty();
  }

  record ParsedSubmit(
      Map<String, String> conf,
      String master,
      String deployMode,
      String proxyUser,
      String jars,
      String primaryResource) {}
}
