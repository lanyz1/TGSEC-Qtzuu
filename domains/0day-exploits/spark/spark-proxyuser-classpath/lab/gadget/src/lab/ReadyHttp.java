package lab;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Readiness and witness oracle. Host publish is 127.0.0.1:18950; the container
 * listener uses the Docker bridge so compose port mapping works.
 */
public final class ReadyHttp {

  static final int PORT = 18950;
  static final Path WITNESS_FILE = Path.of("/work/oracle/SPARK-PROXYUSER-CLASSPATH-WITNESS");

  public static void main(String[] args) throws IOException {
    HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
    server.createContext("/health", ReadyHttp::health);
    server.createContext("/witness", ReadyHttp::witness);
    server.setExecutor(null);
    server.start();
    System.out.println("ready port=" + PORT);
  }

  private static void health(HttpExchange exchange) throws IOException {
    reply(exchange, 200, "ok\n");
  }

  private static void witness(HttpExchange exchange) throws IOException {
    if (!Files.isRegularFile(WITNESS_FILE)) {
      reply(exchange, 404, "missing\n");
      return;
    }
    reply(exchange, 200, Files.readString(WITNESS_FILE, StandardCharsets.UTF_8));
  }

  private static void reply(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }
}
