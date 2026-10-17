package lab;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Stand-in for a tenant jar loaded inside the spark-submit JVM (gateway UID).
 * Writes SPARK-PROXYUSER-CLASSPATH-WITNESS; not a payload.
 */
public final class WitnessMain {

  public static final String TOKEN = "SPARK-PROXYUSER-CLASSPATH-WITNESS";

  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      throw new IllegalArgumentException("usage: lab.WitnessMain <out-path>");
    }
    Path out = Path.of(args[0]);
    Path parent = out.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.writeString(out, TOKEN + "\n", StandardCharsets.UTF_8);
  }
}
