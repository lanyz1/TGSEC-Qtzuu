package lab;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Stub of pin v4.2.0 SparkSubmit.scala prepareSubmitEnvironment:333-336 (allow-flag),
 * 738-743 (YARN cluster copies jars onto childClasspath), and 917-924 (clear() when
 * the SPARK-41958 gate is closed). Default of allowCustomClasspathInClusterMode is
 * false (package.scala:2849-2854). --conf still writes the internal key.
 */
final class SparkSubmit {

  static final String ALLOW_CUSTOM_CLASSPATH_BY_PROXY_USER_IN_CLUSTER_MODE =
      "spark.submit.proxyUser.allowCustomClasspathInClusterMode";

  private SparkSubmit() {}

  static boolean allowCustomClasspath(Map<String, String> sparkConf) {
    return Boolean.parseBoolean(
        sparkConf.getOrDefault(ALLOW_CUSTOM_CLASSPATH_BY_PROXY_USER_IN_CLUSTER_MODE, "false"));
  }

  static boolean isYarnCluster(String master, String deployMode) {
    return "yarn".equals(master) && "cluster".equals(deployMode);
  }

  static boolean isStandAloneCluster(String master, String deployMode) {
    return master != null && master.startsWith("spark") && "cluster".equals(deployMode);
  }

  static boolean isKubernetesCluster(String master, String deployMode) {
    return master != null
        && (master.startsWith("k8s") || master.startsWith("kubernetes"))
        && "cluster".equals(deployMode);
  }

  static boolean isCustomClasspathInClusterModeDisallowed(
      Map<String, String> sparkConf,
      String proxyUser,
      String master,
      String deployMode) {
    return !allowCustomClasspath(sparkConf)
        && proxyUser != null
        && (isYarnCluster(master, deployMode)
            || isStandAloneCluster(master, deployMode)
            || isKubernetesCluster(master, deployMode));
  }

  static List<String> prepareChildClasspath(
      Map<String, String> sparkConf,
      String proxyUser,
      String master,
      String deployMode,
      String primaryResource,
      String jars) {
    List<String> childClasspath = new ArrayList<>();
    if (isYarnCluster(master, deployMode)) {
      if (primaryResource != null && primaryResource.endsWith(".jar")) {
        childClasspath.add(primaryResource);
      }
      if (jars != null && !jars.isEmpty()) {
        for (String jar : jars.split(",")) {
          if (!jar.isEmpty()) {
            childClasspath.add(jar);
          }
        }
      }
    }
    boolean disallowed =
        isCustomClasspathInClusterModeDisallowed(sparkConf, proxyUser, master, deployMode);
    if (!childClasspath.isEmpty() && disallowed) {
      childClasspath.clear();
    }
    return childClasspath;
  }
}
