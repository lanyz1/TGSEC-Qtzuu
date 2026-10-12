/* pin v1.9.3 edbe7f7db12577e905291955a6d416200942fb8b */
/* src/quic/quicengine.cpp:403-407 */
    QuicStream *pStream = new QuicStream();
    ConnInfo *pConnInfo = (ConnInfo *)pStream->getConnInfo();
    UdpListener *pUdpListener = (UdpListener *)lsquic_conn_get_peer_ctx(c,
                                                                        pConnInfo->m_pServerAddrInfo->getAddr());
    pConnInfo->m_pCrypto = pStream;
