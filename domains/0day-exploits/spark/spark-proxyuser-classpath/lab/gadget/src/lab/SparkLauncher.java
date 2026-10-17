package lab;

/**
 * Constants from pin v4.2.0 SparkLauncher.java:59-64 and SPARK_MASTER / DEPLOY_MODE.
 */
final class SparkLauncher {

  static final String SPARK_MASTER = "spark.master";
  static final String DEPLOY_MODE = "spark.submit.deployMode";
  static final String DRIVER_DEFAULT_EXTRA_CLASS_PATH = "spark.driver.defaultExtraClassPath";
  static final String DRIVER_DEFAULT_EXTRA_CLASS_PATH_VALUE = "";
  static final String DRIVER_EXTRA_CLASSPATH = "spark.driver.extraClassPath";

  private SparkLauncher() {}
}
