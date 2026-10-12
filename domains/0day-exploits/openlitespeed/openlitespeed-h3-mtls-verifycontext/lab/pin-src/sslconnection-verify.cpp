/* pin v1.9.3 edbe7f7db12577e905291955a6d416200942fb8b */
/* src/sslpp/sslconnection.cpp:673-676 */
bool SslConnection::verifyContext(SslContext *ctx)
{
    return SSL_get_SSL_CTX(m_ssl) == ctx->get();
}
