// Gadget of OpenLiteSpeed 1.9.3 HTTP/3 Host-vs-SNI mTLS leftover.
// Pin functions: HioCrypto::verifyContext always true; SslConnection pointer
// equality; HttpSession 403 bind; QuicStream does not override; onNewStream
// installs the stream as ConnInfo::m_pCrypto.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

static const char *kWitness = "OLS-H3-MTLS-VERIFYCONTEXT-WITNESS";
static const char *kListen = "0.0.0.0";
static const int kPort = 19200;
static const char *kPinDir = "/lab/pin-src";

class SslContext
{
public:
    explicit SslContext(void *ctx, int verify_mode)
        : m_pCtx(ctx), m_iVerifyMode(verify_mode) {}

    void *get() const { return m_pCtx; }
    int getVerifyMode() const { return m_iVerifyMode; }

private:
    void *m_pCtx;
    int m_iVerifyMode;
};

class HioCrypto
{
public:
    virtual ~HioCrypto() {}
    virtual const char *cryptoKind() const { return "HioCrypto"; }
    // pin src/src/sslpp/hiocrypto.h:49-50
    virtual bool verifyContext(SslContext *ctx)
    {
        (void)ctx;
        return true;
    }
};

class SslConnection : public HioCrypto
{
public:
    explicit SslConnection(void *handshake_ctx) : m_handshakeCtx(handshake_ctx) {}
    const char *cryptoKind() const override { return "SslConnection"; }
    // pin src/src/sslpp/sslconnection.cpp:673-675
    bool verifyContext(SslContext *ctx) override
    {
        return m_handshakeCtx == ctx->get();
    }

private:
    void *m_handshakeCtx;
};

class QuicStream : public HioCrypto
{
public:
    const char *cryptoKind() const override { return "QuicStream"; }
    // pin src/src/quic/quicstream.h: no verifyContext override
};

class HttpVHost
{
public:
    HttpVHost(const char *name, SslContext *ctx) : m_name(name), m_pSSLCtx(ctx) {}
    const char *getName() const { return m_name; }
    SslContext *getSslContext() const { return m_pSSLCtx; }
    // pin src/src/http/httpvhost.cpp:798-801
    int isSslClientAuth() const
    {
        return m_pSSLCtx ? m_pSSLCtx->getVerifyMode() : 0;
    }

private:
    const char *m_name;
    SslContext *m_pSSLCtx;
};

struct ConnInfo
{
    HioCrypto *m_pCrypto;
};

// pin src/src/http/httpsession.cpp:1655-1662
static int sessionBind(HttpVHost *pVHost, HioCrypto *crypto)
{
    if (pVHost->isSslClientAuth() && crypto)
    {
        if (crypto->verifyContext(pVHost->getSslContext()) == false)
            return 403;
    }
    return 200;
}

struct BindCase
{
    std::string transport;
    std::string sni;
    std::string host;
    std::string crypto;
    bool client_auth;
    bool verify_ok;
    int status;
    bool leftover;
    bool served;
};

static void *ctxPublic() { return reinterpret_cast<void *>(0xA); }
static void *ctxMtls() { return reinterpret_cast<void *>(0xB); }

static HttpVHost *selectVHost(const std::string &name, HttpVHost *pub,
                              HttpVHost *mtls)
{
    if (name == "mtls.example" || name == "mtls")
        return mtls;
    if (name == "public.example" || name == "public")
        return pub;
    return 0;
}

static BindCase runBind(const std::string &transport, const std::string &sni,
                        const std::string &host)
{
    SslContext ssl_public(ctxPublic(), 0);
    SslContext ssl_mtls(ctxMtls(), 2);
    HttpVHost v_public("public.example", &ssl_public);
    HttpVHost v_mtls("mtls.example", &ssl_mtls);

    BindCase out;
    out.transport = transport;
    out.sni = sni;
    out.host = host;
    out.crypto = "";
    out.client_auth = false;
    out.verify_ok = false;
    out.status = 400;
    out.leftover = false;
    out.served = false;

    HttpVHost *sni_vhost = selectVHost(sni, &v_public, &v_mtls);
    HttpVHost *host_vhost = selectVHost(host, &v_public, &v_mtls);
    if (!sni_vhost || !host_vhost)
        return out;

    SslConnection tcp(sni_vhost->getSslContext()->get());
    QuicStream h3;
    ConnInfo conn;
    HioCrypto *crypto = 0;
    if (transport == "tcp" || transport == "h1" || transport == "h2")
    {
        crypto = &tcp;
        conn.m_pCrypto = &tcp;
    }
    else if (transport == "h3" || transport == "quic" || transport == "http3")
    {
        // pin src/src/quic/quicengine.cpp:407
        conn.m_pCrypto = &h3;
        crypto = conn.m_pCrypto;
    }
    else
        return out;

    out.crypto = crypto->cryptoKind();
    out.client_auth = host_vhost->isSslClientAuth() != 0;
    out.verify_ok = crypto->verifyContext(host_vhost->getSslContext());
    out.status = sessionBind(host_vhost, crypto);
    out.served = out.status == 200;
    bool tcp_would_403 = false;
    if (host_vhost->isSslClientAuth())
        tcp_would_403 = tcp.verifyContext(host_vhost->getSslContext()) == false;
    out.leftover = (out.crypto == "QuicStream" && out.served && tcp_would_403);
    return out;
}

static std::string jsonEscape(const std::string &s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s)
    {
        if (c == '"' || c == '\\')
        {
            out.push_back('\\');
            out.push_back(c);
        }
        else if (c == '\n')
            out += "\\n";
        else
            out.push_back(c);
    }
    return out;
}

static std::string bindJson(const BindCase &c)
{
    std::ostringstream os;
    os << "{"
       << "\"transport\":\"" << jsonEscape(c.transport) << "\","
       << "\"sni\":\"" << jsonEscape(c.sni) << "\","
       << "\"host\":\"" << jsonEscape(c.host) << "\","
       << "\"crypto\":\"" << jsonEscape(c.crypto) << "\","
       << "\"client_auth\":" << (c.client_auth ? "true" : "false") << ","
       << "\"verify_ok\":" << (c.verify_ok ? "true" : "false") << ","
       << "\"status\":" << c.status << ","
       << "\"leftover\":" << (c.leftover ? "true" : "false") << ","
       << "\"served\":" << (c.served ? "true" : "false") << ","
       << "\"witness\":\""
       << (c.leftover ? kWitness : "") << "\""
       << "}";
    return os.str();
}

static std::string readFile(const std::string &path)
{
    std::ifstream in(path.c_str());
    if (!in)
        return "";
    std::ostringstream os;
    os << in.rdbuf();
    return os.str();
}

static bool contains(const std::string &hay, const std::string &needle)
{
    return hay.find(needle) != std::string::npos;
}

static std::string pinJson()
{
    const std::string hio = readFile(std::string(kPinDir) + "/hiocrypto.h");
    const std::string qstream = readFile(std::string(kPinDir) + "/quicstream.h");
    const std::string qeng = readFile(std::string(kPinDir) + "/quicengine-onnewstream.cpp");
    const std::string ssl = readFile(std::string(kPinDir) + "/sslconnection-verify.cpp");
    const std::string sess = readFile(std::string(kPinDir) + "/httpsession-bind.cpp");

    const bool always_true =
        contains(hio, "virtual bool verifyContext(SslContext *ctx)") &&
        contains(hio, "return true;");
    const bool quic_no_override = !contains(qstream, "verifyContext");
    const bool quic_is_hio = contains(qstream, "public HioCrypto");
    const bool crypto_is_stream = contains(qeng, "pConnInfo->m_pCrypto = pStream;");
    const bool tcp_ptr =
        contains(ssl, "return SSL_get_SSL_CTX(m_ssl) == ctx->get();");
    const bool session_403 =
        contains(sess, "getCrypto()->verifyContext(pVHost->getSslContext())") &&
        contains(sess, "return SC_403;");

    std::ostringstream os;
    os << "{"
       << "\"pin\":\"v1.9.3\","
       << "\"hio_always_true\":" << (always_true ? "true" : "false") << ","
       << "\"quicstream_no_verifycontext\":" << (quic_no_override ? "true" : "false") << ","
       << "\"quicstream_is_hiocrypto\":" << (quic_is_hio ? "true" : "false") << ","
       << "\"quic_crypto_is_stream\":" << (crypto_is_stream ? "true" : "false") << ","
       << "\"tcp_pointer_eq\":" << (tcp_ptr ? "true" : "false") << ","
       << "\"session_bind_403\":" << (session_403 ? "true" : "false") << ","
       << "\"pin_ok\":"
       << (always_true && quic_no_override && quic_is_hio && crypto_is_stream &&
                   tcp_ptr && session_403
               ? "true"
               : "false")
       << "}";
    return os.str();
}

static std::string selfcheckJson()
{
    BindCase tcp_mismatch = runBind("tcp", "public.example", "mtls.example");
    BindCase h3_mismatch = runBind("h3", "public.example", "mtls.example");
    BindCase tcp_match = runBind("tcp", "mtls.example", "mtls.example");
    BindCase h3_public = runBind("h3", "public.example", "public.example");
    const bool ok = tcp_mismatch.status == 403 && h3_mismatch.status == 200 &&
                    h3_mismatch.leftover && tcp_match.status == 200 &&
                    h3_public.status == 200 && !h3_public.leftover;
    std::ostringstream os;
    os << "{"
       << "\"tcp_mismatch\":" << bindJson(tcp_mismatch) << ","
       << "\"h3_mismatch\":" << bindJson(h3_mismatch) << ","
       << "\"tcp_match\":" << bindJson(tcp_match) << ","
       << "\"h3_public\":" << bindJson(h3_public) << ","
       << "\"ok\":" << (ok ? "true" : "false")
       << "}";
    return os.str();
}

static std::string urlDecode(const std::string &in)
{
    std::string out;
    for (size_t i = 0; i < in.size(); ++i)
    {
        if (in[i] == '%' && i + 2 < in.size())
        {
            int v = 0;
            std::istringstream is(in.substr(i + 1, 2));
            if (is >> std::hex >> v)
            {
                out.push_back(static_cast<char>(v));
                i += 2;
                continue;
            }
        }
        else if (in[i] == '+')
        {
            out.push_back(' ');
            continue;
        }
        out.push_back(in[i]);
    }
    return out;
}

static std::map<std::string, std::string> parseQuery(const std::string &q)
{
    std::map<std::string, std::string> out;
    size_t i = 0;
    while (i < q.size())
    {
        size_t amp = q.find('&', i);
        if (amp == std::string::npos)
            amp = q.size();
        const std::string pair = q.substr(i, amp - i);
        size_t eq = pair.find('=');
        if (eq != std::string::npos)
            out[urlDecode(pair.substr(0, eq))] = urlDecode(pair.substr(eq + 1));
        i = amp + 1;
    }
    return out;
}

static void httpReply(int fd, int status, const std::string &ctype,
                      const std::string &body)
{
    const char *reason = status == 200 ? "OK" : "Bad Request";
    std::ostringstream os;
    os << "HTTP/1.1 " << status << " " << reason << "\r\n"
       << "Content-Type: " << ctype << "\r\n"
       << "Content-Length: " << body.size() << "\r\n"
       << "Connection: close\r\n\r\n"
       << body;
    const std::string msg = os.str();
    (void)send(fd, msg.data(), msg.size(), 0);
}

static void handle(int fd)
{
    char buf[4096];
    const ssize_t n = recv(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0)
        return;
    buf[n] = 0;
    std::string req(buf, static_cast<size_t>(n));
    std::string line = req.substr(0, req.find('\n'));
    if (!line.empty() && line[line.size() - 1] == '\r')
        line.resize(line.size() - 1);
    std::istringstream ls(line);
    std::string method, target, ver;
    ls >> method >> target >> ver;
    if (method != "GET")
    {
        httpReply(fd, 400, "text/plain", "method");
        return;
    }
    std::string path = target;
    std::string query;
    size_t qpos = target.find('?');
    if (qpos != std::string::npos)
    {
        path = target.substr(0, qpos);
        query = target.substr(qpos + 1);
    }
    if (path == "/ping")
    {
        httpReply(fd, 200, "text/plain", "pong");
        return;
    }
    if (path == "/pin")
    {
        httpReply(fd, 200, "application/json", pinJson());
        return;
    }
    if (path == "/selfcheck")
    {
        httpReply(fd, 200, "application/json", selfcheckJson());
        return;
    }
    if (path == "/bind")
    {
        std::map<std::string, std::string> kv = parseQuery(query);
        BindCase c = runBind(kv["transport"], kv["sni"], kv["host"]);
        httpReply(fd, 200, "application/json", bindJson(c));
        return;
    }
    if (path.rfind("/pin/", 0) == 0)
    {
        const std::string name = path.substr(5);
        if (name.find("..") != std::string::npos || name.find('/') != std::string::npos)
        {
            httpReply(fd, 400, "text/plain", "path");
            return;
        }
        const std::string body = readFile(std::string(kPinDir) + "/" + name);
        if (body.empty())
        {
            httpReply(fd, 400, "text/plain", "missing");
            return;
        }
        httpReply(fd, 200, "text/plain", body);
        return;
    }
    httpReply(fd, 400, "text/plain", "not-found");
}

int main()
{
    const int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0)
        return 1;
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kPort);
    inet_pton(AF_INET, kListen, &addr.sin_addr);
    if (bind(srv, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0)
        return 1;
    if (listen(srv, 16) != 0)
        return 1;
    for (;;)
    {
        const int fd = accept(srv, 0, 0);
        if (fd < 0)
            continue;
        handle(fd);
        close(fd);
    }
}
