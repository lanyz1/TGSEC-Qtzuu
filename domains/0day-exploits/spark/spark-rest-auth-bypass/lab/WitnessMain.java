package lab;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Worker-UID driver main. REST create launches this via DriverWrapper.
 * CommandUtils.buildLocalCommand injects {@code _SPARK_AUTH_SECRET} when
 * {@code spark.authenticate} is true on the Worker.
 */
public final class WitnessMain {
  private static final String WITNESS = "SPARK-REST-AUTH-BYPASS-WITNESS";

  private WitnessMain() {}

  public static void main(String[] args) throws Exception {
    String dest = args.length > 0 ? args[0] : "/oracle/" + WITNESS;
    String secret = System.getenv("_SPARK_AUTH_SECRET");
    boolean injected = secret != null && !secret.isEmpty();
    String body = WITNESS + "\ninjected=" + (injected ? "yes" : "no") + "\n";
    Path path = Path.of(dest);
    Path parent = path.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.writeString(path, body, StandardCharsets.UTF_8);
    System.out.print(body);
  }
}
