/* pin v1.9.3 edbe7f7db12577e905291955a6d416200942fb8b */
/* src/http/httpsession.cpp:1655-1662 */
    if (pVHost->isSslClientAuth() && getCrypto())
    {
        if (getCrypto()->verifyContext(pVHost->getSslContext()) == false)
        {
            LS_DBG_L(getLogSession(), "VHost [%s] require SSL client authentication, SSL_CTX does not match.",
                     pVHost->getName());
            return SC_403;
        }
