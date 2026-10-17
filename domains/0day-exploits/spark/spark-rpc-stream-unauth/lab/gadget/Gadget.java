import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

/**
 * Lab gadget for Apache Spark 4.2.0 (32f7299601108917fb01920a54e084595b7b3bf8)
 * leftover of CVE-2020-9480 data-plane.
 *
 * Copied sinks:
 *   AbstractAuthRpcHandler.getStreamManager() returns the delegate with no
 *   isAuthenticated check (common/network-common/.../AbstractAuthRpcHandler.java:85-87).
 *   receive / receiveStream stay gated (:52-82).
 *   NettyStreamManager.openStream non-files/jars branch does new File(dir, fname)
 *   (core/.../rpc/netty/NettyStreamManager.scala:54-70). On Unix an absolute child
 *   stays under dir. The leftover walk is fname containing "..".
 *
 * HTTP is a stand-in for TransportRequestHandler: StreamRequest calls
 * getStreamManager().openStream; OneWayMessage calls receive().
 */
public final class Gadget {

  static final String LABEL = "SPARK-RPC-STREAM-UNAUTH";
  static final String WITNESS = "SPARK-RPC-STREAM-UNAUTH-WITNESS";
  static final int PORT = 18910;
  static final String CLASSES_DIR = "/opt/repl-classes";
  static final String AUTH_SECRET = "lab-spark-authenticate-secret";

  private final DelegateRpcHandler delegate;

  Gadget(DelegateRpcHandler delegate) {
    this.delegate = delegate;
  }

  public static void main(String[] args) throws IOException {
    NettyStreamManager streams = new NettyStreamManager();
    streams.addFile(new File(CLASSES_DIR, "hello.txt"));
    streams.addDirectory("classes", new File(CLASSES_DIR));
    Gadget gadget = new Gadget(new DelegateRpcHandler(streams));
    gadget.serve();
  }

  void serve() throws IOException {
    HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
    server.createContext("/ping", this::handlePing);
    server.createContext("/stream", this::handleStream);
    server.createContext("/rpc/receive-stream", this::handleReceiveStream);
    server.createContext("/rpc/receive", this::handleReceive);
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    System.out.println("gadget-listen port=" + PORT + " label=" + LABEL);
    System.out.flush();
  }

  private AbstractAuthRpcHandler newChannel() {
    return new LabAuthRpcHandler(delegate);
  }

  private void handlePing(HttpExchange exchange) throws IOException {
    if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
      sendText(exchange, 405, "method-not-allowed\n");
      return;
    }
    sendText(exchange, 200, "pong " + LABEL + "\n");
  }

  private void handleStream(HttpExchange exchange) throws IOException {
    String streamId = readStreamId(exchange);
    if (streamId == null || streamId.isEmpty()) {
      sendText(exchange, 400, "missing-stream-id\n");
      return;
    }
    AbstractAuthRpcHandler handler = newChannel();
    StreamResult result = new TransportRequestHandler(handler).processStreamRequest(streamId);
    Headers headers = exchange.getResponseHeaders();
    headers.set("X-Lab-How", "gadget");
    headers.set("X-Authenticated", Boolean.toString(handler.isAuthenticated()));
    headers.set("X-Auth-Gated", "false");
    headers.set("X-Ftype", nullToEmpty(result.ftype));
    headers.set("X-Fname", nullToEmpty(result.fname));
    headers.set("X-Opened-Path", nullToEmpty(result.openedPath));
    headers.set("X-Canonical-Path", nullToEmpty(result.canonicalPath));
    headers.set("X-Escaped", Boolean.toString(result.escaped));
    headers.set("X-Parent-Ignored", Boolean.toString(result.parentIgnored));
    if (result.status == 200 && result.body != null) {
      headers.set("Content-Type", "application/octet-stream");
      exchange.sendResponseHeaders(200, result.body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(result.body);
      }
      return;
    }
    sendText(exchange, result.status, result.error + "\n");
  }

  private void handleReceive(HttpExchange exchange) throws IOException {
    if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
      sendText(exchange, 405, "method-not-allowed\n");
      return;
    }
    byte[] body = exchange.getRequestBody().readAllBytes();
    AbstractAuthRpcHandler handler = newChannel();
    Headers headers = exchange.getResponseHeaders();
    headers.set("X-Lab-How", "gadget");
    headers.set("X-Auth-Gated", "true");
    try {
      handler.receiveOneWay(body);
      headers.set("X-Authenticated", Boolean.toString(handler.isAuthenticated()));
      sendText(exchange, 200, "receive-ok\n");
    } catch (SecurityException exc) {
      headers.set("X-Authenticated", "false");
      sendText(exchange, 401, exc.getMessage() + "\n");
    }
  }

  private void handleReceiveStream(HttpExchange exchange) throws IOException {
    if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
      sendText(exchange, 405, "method-not-allowed\n");
      return;
    }
    byte[] body = exchange.getRequestBody().readAllBytes();
    AbstractAuthRpcHandler handler = newChannel();
    Headers headers = exchange.getResponseHeaders();
    headers.set("X-Lab-How", "gadget");
    headers.set("X-Auth-Gated", "true");
    try {
      if (AUTH_SECRET.equals(new String(body, StandardCharsets.UTF_8).trim())) {
        handler.authenticateForLab();
      }
      handler.receiveStream();
      headers.set("X-Authenticated", "true");
      sendText(exchange, 200, "receiveStream-ok\n");
    } catch (SecurityException exc) {
      headers.set("X-Authenticated", "false");
      sendText(exchange, 401, exc.getMessage() + "\n");
    }
  }

  private static String readStreamId(HttpExchange exchange) throws IOException {
    String query = exchange.getRequestURI().getRawQuery();
    if (query != null) {
      for (String pair : query.split("&")) {
        int eq = pair.indexOf('=');
        if (eq <= 0) {
          continue;
        }
        String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
        if ("id".equals(key)) {
          return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
        }
      }
    }
    if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
      return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).trim();
    }
    return null;
  }

  private static void sendText(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.sendResponseHeaders(status, bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private static String nullToEmpty(String value) {
    return value == null ? "" : value;
  }

  /**
   * Copied from AbstractAuthRpcHandler.java:52-87. receive / receiveStream require
   * isAuthenticated. getStreamManager() does not.
   */
  abstract static class AbstractAuthRpcHandler {
    private final RpcHandler delegate;
    private boolean isAuthenticated;

    protected AbstractAuthRpcHandler(RpcHandler delegate) {
      this.delegate = delegate;
    }

    protected abstract boolean doAuthChallenge(byte[] message);

    /** OneWayMessage path: AbstractAuthRpcHandler.java:64-70. */
    public final void receiveOneWay(byte[] message) {
      if (isAuthenticated) {
        delegate.receive(message);
        return;
      }
      throw new SecurityException("Unauthenticated call to receive().");
    }

    public final void receiveStream() {
      if (isAuthenticated) {
        delegate.receiveStream();
        return;
      }
      throw new SecurityException("Unauthenticated call to receiveStream().");
    }

    public StreamManager getStreamManager() {
      return delegate.getStreamManager();
    }

    public boolean isAuthenticated() {
      return isAuthenticated;
    }

    void authenticateForLab() {
      isAuthenticated = true;
    }
  }

  static final class LabAuthRpcHandler extends AbstractAuthRpcHandler {
    LabAuthRpcHandler(RpcHandler delegate) {
      super(delegate);
    }

    @Override
    protected boolean doAuthChallenge(byte[] message) {
      String offered = new String(message, StandardCharsets.UTF_8).trim();
      return AUTH_SECRET.equals(offered);
    }
  }

  abstract static class RpcHandler {
    abstract StreamManager getStreamManager();

    void receive(byte[] message) {
      // Authenticated control-plane stand-in. Job submit stays behind this gate.
    }

    void receiveStream() {
      // Authenticated UploadStream stand-in.
    }
  }

  static final class DelegateRpcHandler extends RpcHandler {
    private final StreamManager streams;

    DelegateRpcHandler(StreamManager streams) {
      this.streams = streams;
    }

    @Override
    StreamManager getStreamManager() {
      return streams;
    }
  }

  abstract static class StreamManager {
    void checkAuthorization(String streamId) {
      // Default StreamManager.checkAuthorization is a no-op (StreamManager.java:84).
    }

    abstract OpenedStream openStream(String streamId);
  }

  /**
   * Copied from NettyStreamManager.scala:54-70. files/jars are map lookups.
   * Any other ftype does new File(dir, fname) with no stay-under-root check.
   */
  static final class NettyStreamManager extends StreamManager {
    private final Map<String, File> files = new ConcurrentHashMap<>();
    private final Map<String, File> jars = new ConcurrentHashMap<>();
    private final Map<String, File> dirs = new ConcurrentHashMap<>();

    void addFile(File file) {
      files.put(file.getName(), file.getAbsoluteFile());
    }

    void addDirectory(String baseUri, File path) {
      String key = baseUri.startsWith("/") ? baseUri.substring(1) : baseUri;
      dirs.put(key, path.getAbsoluteFile());
    }

    @Override
    OpenedStream openStream(String streamId) {
      String stripped = streamId.startsWith("/") ? streamId.substring(1) : streamId;
      String[] parts = stripped.split("/", 2);
      if (parts.length != 2) {
        throw new IllegalArgumentException("Invalid stream URI: " + streamId);
      }
      String ftype = parts[0];
      String fname = parts[1];
      File dir = null;
      File file;
      switch (ftype) {
        case "files" -> file = files.get(fname);
        case "jars" -> file = jars.get(fname);
        default -> {
          dir = dirs.get(ftype);
          if (dir == null) {
            throw new IllegalArgumentException("Invalid stream URI: " + ftype + " not found.");
          }
          // Spark: new File(dir, fname) with no stay-under-root check.
          file = new File(dir, fname);
        }
      }
      boolean parentIgnored = file != null && fname.startsWith("/") && file.getPath().equals(fname);
      String opened = file == null ? "" : file.getPath();
      String canonical = canonicalOrEmpty(file);
      boolean escaped = isEscaped(dir, file);
      if (file != null && file.isFile()) {
        try {
          byte[] body = Files.readAllBytes(file.toPath());
          return OpenedStream.found(
              ftype, fname, opened, canonical, parentIgnored, escaped, body);
        } catch (IOException exc) {
          throw new IllegalStateException("read-failed " + opened, exc);
        }
      }
      return OpenedStream.missing(ftype, fname, opened, canonical, parentIgnored, escaped);
    }

    private static String canonicalOrEmpty(File file) {
      if (file == null) {
        return "";
      }
      try {
        return file.getCanonicalPath();
      } catch (IOException exc) {
        return "";
      }
    }

    private static boolean isEscaped(File dir, File file) {
      if (dir == null || file == null) {
        return false;
      }
      try {
        String root = dir.getCanonicalPath();
        String target = file.getCanonicalPath();
        return !target.equals(root) && !target.startsWith(root + File.separator);
      } catch (IOException exc) {
        return false;
      }
    }
  }

  /**
   * Stand-in for TransportRequestHandler.processStreamRequest (java:125-164).
   * Does not call rpcHandler.receive. Uses getStreamManager() then openStream.
   */
  static final class TransportRequestHandler {
    private final AbstractAuthRpcHandler rpcHandler;

    TransportRequestHandler(AbstractAuthRpcHandler rpcHandler) {
      this.rpcHandler = rpcHandler;
    }

    StreamResult processStreamRequest(String streamId) {
      StreamManager streamManager = rpcHandler.getStreamManager();
      try {
        streamManager.checkAuthorization(streamId);
        OpenedStream opened = streamManager.openStream(streamId);
        if (opened.found) {
          return StreamResult.ok(opened);
        }
        return StreamResult.notFound(opened, "Stream '" + streamId + "' was not found.");
      } catch (IllegalArgumentException | IllegalStateException exc) {
        return StreamResult.error(400, exc.getMessage());
      }
    }
  }

  static final class OpenedStream {
    final boolean found;
    final String ftype;
    final String fname;
    final String openedPath;
    final String canonicalPath;
    final boolean parentIgnored;
    final boolean escaped;
    final byte[] body;

    private OpenedStream(
        boolean found,
        String ftype,
        String fname,
        String openedPath,
        String canonicalPath,
        boolean parentIgnored,
        boolean escaped,
        byte[] body) {
      this.found = found;
      this.ftype = ftype;
      this.fname = fname;
      this.openedPath = openedPath;
      this.canonicalPath = canonicalPath;
      this.parentIgnored = parentIgnored;
      this.escaped = escaped;
      this.body = body;
    }

    static OpenedStream found(
        String ftype,
        String fname,
        String openedPath,
        String canonicalPath,
        boolean parentIgnored,
        boolean escaped,
        byte[] body) {
      return new OpenedStream(
          true, ftype, fname, openedPath, canonicalPath, parentIgnored, escaped, body);
    }

    static OpenedStream missing(
        String ftype,
        String fname,
        String openedPath,
        String canonicalPath,
        boolean parentIgnored,
        boolean escaped) {
      return new OpenedStream(
          false, ftype, fname, openedPath, canonicalPath, parentIgnored, escaped, null);
    }
  }

  static final class StreamResult {
    final int status;
    final String ftype;
    final String fname;
    final String openedPath;
    final String canonicalPath;
    final boolean parentIgnored;
    final boolean escaped;
    final byte[] body;
    final String error;

    private StreamResult(
        int status,
        String ftype,
        String fname,
        String openedPath,
        String canonicalPath,
        boolean parentIgnored,
        boolean escaped,
        byte[] body,
        String error) {
      this.status = status;
      this.ftype = ftype;
      this.fname = fname;
      this.openedPath = openedPath;
      this.canonicalPath = canonicalPath;
      this.parentIgnored = parentIgnored;
      this.escaped = escaped;
      this.body = body;
      this.error = error;
    }

    static StreamResult ok(OpenedStream opened) {
      return new StreamResult(
          200,
          opened.ftype,
          opened.fname,
          opened.openedPath,
          opened.canonicalPath,
          opened.parentIgnored,
          opened.escaped,
          opened.body,
          "");
    }

    static StreamResult notFound(OpenedStream opened, String error) {
      return new StreamResult(
          404,
          opened.ftype,
          opened.fname,
          opened.openedPath,
          opened.canonicalPath,
          opened.parentIgnored,
          opened.escaped,
          null,
          error);
    }

    static StreamResult error(int status, String error) {
      return new StreamResult(status, "", "", "", "", false, false, null, error);
    }
  }
}
