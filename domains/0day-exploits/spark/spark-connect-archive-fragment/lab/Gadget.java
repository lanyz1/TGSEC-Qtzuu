/*
 * Gadget of Apache Spark 4.2.0 Connect archive # fragment leftover (G4).
 * Pin tag v4.2.0 commit 32f7299601108917fb01920a54e084595b7b3bf8.
 *
 * Copied:
 *   SparkConnectAddArtifactsHandler.StagedArtifact archives/ # split
 *     (SparkConnectAddArtifactsHandler.scala:202-213). Fragment is NOT
 *     passed through concatenatePaths.
 *   ArtifactUtils.concatenatePaths (ArtifactUtils.scala:26-39).
 *   ArtifactManager archives/ URI fragment then SparkContext.addArchive
 *     (ArtifactManager.scala:269-274).
 *   SparkContext dest = new File(root, uri.getFragment) then
 *     deleteRecursively + unpack (SparkContext.scala:1891-1900). Same dest
 *     construction on executors (Executor.scala:1468-1477).
 *
 * Zip unpack is dest-contained (Hadoop FileUtil.unZip / HADOOP-13649 class).
 * Member zip-slip is not this leftover; the dest itself is.
 */

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.security.auth.module.UnixSystem;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public final class Gadget {
    static final String LABEL = "SPARK-CONNECT-ARCHIVE-FRAGMENT";
    static final String WITNESS = "SPARK-CONNECT-ARCHIVE-FRAGMENT-WITNESS";
    static final String PIN = "v4.2.0";
    static final String PIN_COMMIT = "32f7299601108917fb01920a54e084595b7b3bf8";
    static final int PORT = 18930;
    static final int MAX_BODY = 2 * 1024 * 1024;

    static final Path ROOT = Paths.get("/lab/root");
    static final Path STAGING = Paths.get("/lab/staging");
    static final Path ORACLE = Paths.get("/lab/oracle");
    static final File ROOT_FILE = ROOT.toFile();

    static final long UID = new UnixSystem().getUid();

    private Gadget() {}

    /** ArtifactUtils.scala:26-39 */
    static Path concatenatePaths(Path basePath, Path otherPath) {
        if (otherPath.isAbsolute()) {
            throw new IllegalArgumentException("INVALID_ARTIFACT_PATH");
        }
        Path concatenatedPath = Paths.get(basePath.toString() + "/" + otherPath.toString());
        Path normalizedPath = concatenatedPath.normalize();
        if (normalizedPath.equals(basePath)
                || !normalizedPath.startsWith(basePath.toString() + "/")) {
            throw new IllegalArgumentException("INVALID_ARTIFACT_PATH");
        }
        return normalizedPath;
    }

    /** SparkConnectAddArtifactsHandler.scala:202-213 */
    static NameParts splitArchiveName(String name) {
        if (name.startsWith("archives" + File.separator)) {
            String[] splits = name.split("#");
            if (splits.length > 2) {
                throw new IllegalArgumentException("hash-in-path-not-supported");
            }
            if (splits.length == 2) {
                return new NameParts(splits[0], splits[1]);
            }
            return new NameParts(splits[0], null);
        }
        return new NameParts(name, null);
    }

    /** SparkFileUtils.deleteRecursively / JavaUtils.deleteRecursively */
    static void deleteRecursively(File file) throws IOException {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isDirectory() && !Files.isSymbolicLink(file.toPath())) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursively(child);
                }
            }
        }
        if (!file.delete() && file.exists()) {
            throw new IOException("delete-failed:" + file.getPath());
        }
    }

    /**
     * Utils.unpack zip branch (Utils.scala:455-457): Hadoop FileUtil.unZip
     * into dest. Members that escape dest are rejected (not this leftover).
     */
    static void unpackZip(File source, File dest) throws IOException {
        if (!source.exists()) {
            throw new IOException("source-missing:" + source.getPath());
        }
        if (!dest.mkdirs() && !dest.isDirectory()) {
            throw new IOException("mkdirs-failed:" + dest.getPath());
        }
        Path destCanon = dest.getCanonicalFile().toPath();
        try (ZipFile zip = new ZipFile(source)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                File out = new File(dest, entry.getName());
                Path outCanon = out.getCanonicalFile().toPath();
                if (!outCanon.startsWith(destCanon)) {
                    throw new IOException("zip-member-escapes-dest");
                }
                if (entry.isDirectory()) {
                    if (!out.mkdirs() && !out.isDirectory()) {
                        throw new IOException("mkdir-failed:" + out.getPath());
                    }
                    continue;
                }
                File parent = out.getParentFile();
                if (parent != null && !parent.mkdirs() && !parent.isDirectory()) {
                    throw new IOException("mkdir-failed:" + parent.getPath());
                }
                try (InputStream in = zip.getInputStream(entry);
                        OutputStream os = new FileOutputStream(out)) {
                    in.transferTo(os);
                }
            }
        }
    }

    static AddResult addArtifact(String name, byte[] body) throws IOException {
        NameParts parts = splitArchiveName(name);
        Path stagedPath = concatenatePaths(STAGING, Paths.get(parts.canonicalFileName));
        Files.createDirectories(stagedPath.getParent());
        Files.write(stagedPath, body);

        boolean isArchive = parts.canonicalFileName.startsWith("archives" + File.separator);
        if (!isArchive) {
            return AddResult.stagedOnly(name, parts, stagedPath);
        }

        URI archiveUri;
        try {
            archiveUri =
                    new URI("file", null, stagedPath.toAbsolutePath().toString(), parts.fragment);
        } catch (URISyntaxException ex) {
            throw new IOException("uri:" + ex.getMessage(), ex);
        }
        String fragment = archiveUri.getFragment();
        File source = stagedPath.toFile();
        // SparkContext.scala:1891-1893
        File dest =
                new File(ROOT_FILE, fragment != null ? fragment : source.getName());
        boolean existed = dest.exists();
        deleteRecursively(dest);
        unpackZip(source, dest);
        return AddResult.unpacked(name, parts, stagedPath, archiveUri, dest, existed);
    }

    static void seedLayout() throws IOException {
        Files.createDirectories(ROOT);
        Files.createDirectories(STAGING);
        Files.createDirectories(ORACLE);
        Path keep = ORACLE.resolve("canary-keep.txt");
        Files.writeString(keep, "keep\n", StandardCharsets.UTF_8);
        Path destDir = ORACLE.resolve(WITNESS);
        Files.createDirectories(destDir);
        Files.writeString(destDir.resolve("canary.txt"), "canary\n", StandardCharsets.UTF_8);
        Path absDest = ORACLE.resolve("abs-" + WITNESS);
        Files.createDirectories(absDest);
        Files.writeString(absDest.resolve("canary.txt"), "canary\n", StandardCharsets.UTF_8);
    }

    static void selfTest() throws Exception {
        Path tmpBase = Files.createTempDirectory("concat");
        try {
            concatenatePaths(tmpBase, Paths.get("archives/payload.zip"));
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("concat-safe-rejected", ex);
        }
        try {
            concatenatePaths(tmpBase, Paths.get("files/../../oracle/x"));
            throw new IllegalStateException("concat-dotdot-accepted");
        } catch (IllegalArgumentException expected) {
            // adjacent files/jars path concat stays closed
        }
        NameParts split = splitArchiveName("archives/payload.zip#../oracle/" + WITNESS);
        if (!"archives/payload.zip".equals(split.canonicalFileName)) {
            throw new IllegalStateException("canonical:" + split.canonicalFileName);
        }
        if (!("../oracle/" + WITNESS).equals(split.fragment)) {
            throw new IllegalStateException("fragment:" + split.fragment);
        }
        NameParts files = splitArchiveName("files/payload.zip#../oracle/" + WITNESS);
        if (files.fragment != null) {
            throw new IllegalStateException("files-split-kept-fragment");
        }
        File rel = new File(ROOT_FILE, "../oracle/" + WITNESS);
        if (!rel.getCanonicalFile().equals(ORACLE.resolve(WITNESS).toFile().getCanonicalFile())) {
            throw new IllegalStateException("rel-dest:" + rel.getCanonicalPath());
        }
        // Unix File(parent, absChild) strips the leading slash and joins under
        // parent. Parent is ignored only on Windows. The leftover on Linux is
        // the relative fragment with parent tokens.
        File abs = new File(ROOT_FILE, "/lab/oracle/abs-" + WITNESS);
        String unixAbs = ROOT.toString() + "/lab/oracle/abs-" + WITNESS;
        if (!unixAbs.equals(abs.getPath())) {
            throw new IllegalStateException("unix-abs-join:" + abs.getPath());
        }
        System.out.println(
                "self-test ok pin=" + PIN + " commit=" + PIN_COMMIT + " uid=" + UID);
        System.out.flush();
    }

    static boolean allowedPrefix(Path path) {
        String normalized = path.toAbsolutePath().normalize().toString();
        return normalized.equals("/lab/root")
                || normalized.startsWith("/lab/root/")
                || normalized.equals("/lab/staging")
                || normalized.startsWith("/lab/staging/")
                || normalized.equals("/lab/oracle")
                || normalized.startsWith("/lab/oracle/");
    }

    static void handle(HttpExchange ex) throws IOException {
        try {
            String method = ex.getRequestMethod();
            String path = ex.getRequestURI().getPath();
            if ("GET".equals(method) && "/ping".equals(path)) {
                byte[] body = "pong\n".getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().add("X-Lab-How", "gadget");
                ex.getResponseHeaders().add("X-Pin", PIN);
                ex.getResponseHeaders().add("X-Uid", Long.toString(UID));
                send(ex, 200, "text/plain; charset=utf-8", body);
                return;
            }
            if ("GET".equals(method) && "/meta".equals(path)) {
                Map<String, String> fields = new LinkedHashMap<>();
                fields.put("ok", "true");
                fields.put("label", LABEL);
                fields.put("witness", WITNESS);
                fields.put("pin", PIN);
                fields.put("commit", PIN_COMMIT);
                fields.put("uid", Long.toString(UID));
                fields.put("root", ROOT.toString());
                fields.put("staging", STAGING.toString());
                fields.put("oracle", ORACLE.toString());
                sendJson(ex, 200, fields);
                return;
            }
            if ("GET".equals(method) && "/stat".equals(path)) {
                String target = query(ex.getRequestURI(), "path");
                handleStat(ex, target);
                return;
            }
            if ("GET".equals(method) && "/cat".equals(path)) {
                String target = query(ex.getRequestURI(), "path");
                handleCat(ex, target);
                return;
            }
            if ("POST".equals(method) && "/add-artifact".equals(path)) {
                handleAdd(ex);
                return;
            }
            sendJson(ex, 404, Map.of("ok", "false", "error", "not-found"));
        } catch (Exception err) {
            sendJson(
                    ex,
                    500,
                    Map.of(
                            "ok",
                            "false",
                            "error",
                            jsonEscape(err.getClass().getSimpleName() + ":" + err.getMessage())));
        } finally {
            ex.close();
        }
    }

    static void handleAdd(HttpExchange ex) throws Exception {
        String name = header(ex, "X-Artifact-Name");
        if (name == null || name.isEmpty()) {
            sendJson(ex, 400, Map.of("ok", "false", "error", "missing-name"));
            return;
        }
        byte[] body = readBody(ex);
        try {
            AddResult result = addArtifact(name, body);
            sendJson(ex, 200, result.fields());
        } catch (IllegalArgumentException err) {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("ok", "false");
            fields.put("error", err.getMessage() == null ? "invalid" : err.getMessage());
            fields.put("name", name);
            sendJson(ex, 400, fields);
        }
    }

    static void handleStat(HttpExchange ex, String target) throws IOException {
        if (target == null || target.isEmpty()) {
            sendJson(ex, 400, Map.of("ok", "false", "error", "missing-path"));
            return;
        }
        Path path = Paths.get(target);
        if (!path.isAbsolute() || !allowedPrefix(path)) {
            sendJson(ex, 403, Map.of("ok", "false", "error", "path-not-allowlisted"));
            return;
        }
        File file = path.toFile();
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("ok", "true");
        fields.put("path", path.toString());
        fields.put("exists", Boolean.toString(file.exists()));
        if (!file.exists()) {
            sendJson(ex, 200, fields);
            return;
        }
        Path canon = file.getCanonicalFile().toPath();
        if (!allowedPrefix(canon)) {
            sendJson(ex, 403, Map.of("ok", "false", "error", "path-not-allowlisted"));
            return;
        }
        int uid = (Integer) Files.getAttribute(canon, "unix:uid");
        fields.put("canonical", canon.toString());
        fields.put("uid", Integer.toString(uid));
        fields.put("directory", Boolean.toString(Files.isDirectory(canon)));
        fields.put("size", Long.toString(Files.size(canon)));
        fields.put("outsideRoot", Boolean.toString(outsideRoot(canon.toFile())));
        sendJson(ex, 200, fields);
    }

    static void handleCat(HttpExchange ex, String target) throws IOException {
        if (target == null || target.isEmpty()) {
            sendJson(ex, 400, Map.of("ok", "false", "error", "missing-path"));
            return;
        }
        Path path = Paths.get(target);
        if (!path.isAbsolute() || !allowedPrefix(path)) {
            sendJson(ex, 403, Map.of("ok", "false", "error", "path-not-allowlisted"));
            return;
        }
        if (!Files.exists(path)) {
            sendJson(ex, 404, Map.of("ok", "false", "error", "missing"));
            return;
        }
        Path canon = path.toRealPath();
        if (!allowedPrefix(canon) || Files.isDirectory(canon)) {
            sendJson(ex, 403, Map.of("ok", "false", "error", "path-not-allowlisted"));
            return;
        }
        byte[] body = Files.readAllBytes(canon);
        ex.getResponseHeaders().add("X-Uid", Files.getAttribute(canon, "unix:uid").toString());
        send(ex, 200, "text/plain; charset=utf-8", body);
    }

    static boolean outsideRoot(File dest) throws IOException {
        File destCanon = dest.getCanonicalFile();
        File rootCanon = ROOT_FILE.getCanonicalFile();
        String destPath = destCanon.getPath();
        String rootPath = rootCanon.getPath();
        return !destPath.equals(rootPath) && !destPath.startsWith(rootPath + File.separator);
    }

    static byte[] readBody(HttpExchange ex) throws IOException {
        long claimed = ex.getRequestHeaders().getFirst("Content-Length") == null
                ? -1
                : Long.parseLong(ex.getRequestHeaders().getFirst("Content-Length"));
        if (claimed > MAX_BODY) {
            throw new IOException("body-too-large");
        }
        try (InputStream in = ex.getRequestBody();
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            int total = 0;
            while ((n = in.read(buf)) >= 0) {
                total += n;
                if (total > MAX_BODY) {
                    throw new IOException("body-too-large");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    static String header(HttpExchange ex, String name) {
        return ex.getRequestHeaders().getFirst(name);
    }

    static String query(URI uri, String key) {
        String raw = uri.getRawQuery();
        if (raw == null) {
            return null;
        }
        for (String part : raw.split("&")) {
            int eq = part.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String k = java.net.URLDecoder.decode(part.substring(0, eq), StandardCharsets.UTF_8);
            if (key.equals(k)) {
                return java.net.URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    static void sendJson(HttpExchange ex, int status, Map<String, String> fields)
            throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(jsonEscape(entry.getKey())).append('"').append(':');
            String value = entry.getValue();
            if ("true".equals(value) || "false".equals(value) || "null".equals(value)
                    || isJsonNumber(value)) {
                sb.append(value);
            } else if (value == null) {
                sb.append("null");
            } else {
                sb.append('"').append(jsonEscape(value)).append('"');
            }
        }
        sb.append('}');
        send(ex, status, "application/json; charset=utf-8",
                sb.toString().getBytes(StandardCharsets.UTF_8));
    }

    static boolean isJsonNumber(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '-' && (c < '0' || c > '9')) {
                return false;
            }
        }
        return true;
    }

    static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 32) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    static void send(HttpExchange ex, int status, String ctype, byte[] body) throws IOException {
        ex.getResponseHeaders().add("Content-Type", ctype);
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    public static void main(String[] args) throws Exception {
        seedLayout();
        selfTest();
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);
        server.createContext("/", Gadget::handle);
        server.setExecutor(null);
        server.start();
        System.out.println(
                "gadget listen 0.0.0.0:" + PORT + " label=" + LABEL + " uid=" + UID);
        System.out.flush();
    }

    static final class NameParts {
        final String canonicalFileName;
        final String fragment;

        NameParts(String canonicalFileName, String fragment) {
            this.canonicalFileName = canonicalFileName;
            this.fragment = fragment;
        }
    }

    static final class AddResult {
        final String name;
        final NameParts parts;
        final Path stagedPath;
        final URI archiveUri;
        final File dest;
        final boolean destExisted;
        final boolean unpacked;

        AddResult(
                String name,
                NameParts parts,
                Path stagedPath,
                URI archiveUri,
                File dest,
                boolean destExisted,
                boolean unpacked) {
            this.name = name;
            this.parts = parts;
            this.stagedPath = stagedPath;
            this.archiveUri = archiveUri;
            this.dest = dest;
            this.destExisted = destExisted;
            this.unpacked = unpacked;
        }

        static AddResult stagedOnly(String name, NameParts parts, Path stagedPath) {
            return new AddResult(name, parts, stagedPath, null, null, false, false);
        }

        static AddResult unpacked(
                String name,
                NameParts parts,
                Path stagedPath,
                URI archiveUri,
                File dest,
                boolean destExisted) {
            return new AddResult(name, parts, stagedPath, archiveUri, dest, destExisted, true);
        }

        Map<String, String> fields() throws IOException {
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("ok", "true");
            fields.put("name", name);
            fields.put("canonicalFileName", parts.canonicalFileName);
            fields.put("fragment", parts.fragment == null ? "null" : parts.fragment);
            fields.put("fragmentPresent", Boolean.toString(parts.fragment != null));
            fields.put("stagedPath", stagedPath.toString());
            fields.put("uid", Long.toString(UID));
            fields.put("unpacked", Boolean.toString(unpacked));
            if (archiveUri != null) {
                fields.put("archiveUri", archiveUri.toString());
                fields.put(
                        "uriFragment",
                        archiveUri.getFragment() == null ? "null" : archiveUri.getFragment());
            }
            if (dest != null) {
                fields.put("dest", dest.getPath());
                fields.put("destAbsolute", dest.getAbsolutePath());
                fields.put("destCanonical", dest.getCanonicalPath());
                fields.put("destOutsideRoot", Boolean.toString(outsideRoot(dest)));
                fields.put("deletedRecursively", Boolean.toString(destExisted));
                File pwned = new File(dest, "pwned.txt");
                fields.put("pwned", pwned.getCanonicalPath());
                fields.put("pwnedExists", Boolean.toString(pwned.isFile()));
            }
            return fields;
        }
    }
}
