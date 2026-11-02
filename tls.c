/* Native Windows transport. No OpenSSL dependency or private-key export. */
#define _WIN32_WINNT 0x0601
#define SECURITY_WIN32
#define SCHANNEL_USE_BLACKLISTS
#include <winsock2.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ncrypt.h>
#include "tls.h"
#include "tls_endpoint.h"

extern void mrlog(char *, ...);

#define TLS_INPUT_SIZE (128 * 1024)
#define TLS_FLAGS (ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | \
    ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | \
    ISC_REQ_STREAM | ISC_REQ_MANUAL_CRED_VALIDATION)

struct tls_connection {
    SOCKET socket;
    CredHandle credentials;
    CtxtHandle context;
    int have_credentials;
    int have_context;
    ULONGLONG deadline;
    const char *stage;
    DWORD error;
    int diagnostic;
};

static volatile LONG cancelled;

void mr_tls_cancel(void)
{
    InterlockedExchange(&cancelled, 1);
}

static int active(struct tls_connection *c)
{
    if (InterlockedCompareExchange(&cancelled, 0, 0)) {
        c->error = ERROR_OPERATION_ABORTED;
        return 0;
    }
    if (GetTickCount64() >= c->deadline) {
        c->error = WAIT_TIMEOUT;
        return 0;
    }
    return 1;
}

static int wait_socket(struct tls_connection *c, int writing)
{
    fd_set ready, errors;
    struct timeval timeout;
    ULONGLONG remaining;
    int result;
    while (active(c)) {
    {
        ULONGLONG now = GetTickCount64();
        if (now >= c->deadline) continue;
        remaining = c->deadline - now;
    }
    if (remaining > 100) remaining = 100; /* observe service cancellation promptly */
    timeout.tv_sec = 0;
    timeout.tv_usec = (long)(remaining * 1000);
    FD_ZERO(&ready);
    FD_ZERO(&errors);
    FD_SET(c->socket, &ready);
    FD_SET(c->socket, &errors);
    result = select(0, writing ? NULL : &ready, writing ? &ready : NULL,
                    &errors, &timeout);
    if (result == SOCKET_ERROR) {
        c->error = (DWORD)WSAGetLastError();
        return 0;
    }
    if (result > 0) return 1; /* caller checks SO_ERROR/recv/send, including reset */
    }
    return 0;
}

static int send_all(struct tls_connection *c, const void *data, size_t length)
{
    const char *p = data;
    while (length) {
        int sent;
        if (!wait_socket(c, 1)) return 0;
        sent = send(c->socket, p, (int)(length > INT_MAX ? INT_MAX : length), 0);
        if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (sent <= 0) {
            c->error = sent ? (DWORD)WSAGetLastError() : WSAECONNRESET;
            return 0;
        }
        p += sent;
        length -= sent;
    }
    return 1;
}

static PCCERT_CONTEXT client_certificate(const char *thumbprint)
{
    BYTE hash[20];
    CRYPT_HASH_BLOB blob;
    HCERTSTORE store;
    PCCERT_CONTEXT certificate;
    unsigned int i;
    if (strlen(thumbprint) != 40) return NULL;
    for (i = 0; i < sizeof(hash); ++i) {
        unsigned int byte;
        char pair[3] = {thumbprint[i * 2], thumbprint[i * 2 + 1], 0};
        if (!strchr("0123456789abcdefABCDEF", pair[0]) ||
            !strchr("0123456789abcdefABCDEF", pair[1]) ||
            sscanf(pair, "%2x", &byte) != 1) return NULL;
        hash[i] = (BYTE)byte;
    }
    blob.cbData = sizeof(hash);
    blob.pbData = hash;
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                         CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG,
                         "MY");
    if (!store) return NULL;
    certificate = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
                                             CERT_FIND_SHA1_HASH, &blob, NULL);
    CertCloseStore(store, 0);
    return certificate;
}

static int supplied_crl_valid(PCCRL_CONTEXT crl, PCCERT_CHAIN_CONTEXT chain)
{
    DWORD i, j;
    if ((!crl->pCrlInfo->NextUpdate.dwLowDateTime &&
         !crl->pCrlInfo->NextUpdate.dwHighDateTime) ||
        CertVerifyCRLTimeValidity(NULL, crl->pCrlInfo)) return 0;
    for (i = 0; i < chain->cChain; ++i) {
        PCERT_SIMPLE_CHAIN simple = chain->rgpChain[i];
        for (j = 0; j + 1 < simple->cElement; ++j) {
            PCCERT_CONTEXT subject = simple->rgpElement[j]->pCertContext;
            PCCERT_CONTEXT issuer = simple->rgpElement[j + 1]->pCertContext;
            PCRL_ENTRY entry = NULL;
            BYTE usage = 0;
            if (!CertCompareCertificateName(X509_ASN_ENCODING, &crl->pCrlInfo->Issuer,
                                             &issuer->pCertInfo->Subject)) continue;
            if (!CertIsValidCRLForCertificate(subject, crl, 0, NULL)) continue;
            if (CertGetIntendedKeyUsage(X509_ASN_ENCODING, issuer->pCertInfo,
                                        &usage, sizeof(usage)) && !(usage & CERT_CRL_SIGN_KEY_USAGE))
                return 0;
            if (!CryptVerifyCertificateSignatureEx(0, X509_ASN_ENCODING,
                    CRYPT_VERIFY_CERT_SIGN_SUBJECT_CRL, (void *)crl,
                    CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void *)issuer, 0, NULL) ||
                !CertFindCertificateInCRL(subject, crl, 0, NULL, &entry) || entry)
                return 0;
            return 1;
        }
    }
    return 0;
}

static int verify_server(struct tls_connection *c, const char *name,
                         const struct mr_tls_config *config)
{
    PCCERT_CONTEXT peer = NULL, root = NULL;
    PCCRL_CONTEXT crl = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    HCERTSTORE roots = NULL, additional = NULL, collection = NULL;
    HCERTCHAINENGINE engine = NULL;
    CERT_CHAIN_ENGINE_CONFIG engine_config;
    CERT_CHAIN_PARA parameters;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_policy;
    CERT_CHAIN_POLICY_PARA policy;
    CERT_CHAIN_POLICY_STATUS status;
    WCHAR server_name[256], root_path[MAX_PATH];
    LPSTR usage = szOID_PKIX_KP_SERVER_AUTH;
    int ok = 0;

    memset(&status, 0, sizeof(status));
    c->stage = "server-chain";
    c->error = 0;

    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1,
                             server_name, 256)) goto cleanup;
    if (QueryContextAttributes(&c->context, SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                               &peer) != SEC_E_OK) goto cleanup;
    additional = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    collection = CertOpenStore(CERT_STORE_PROV_COLLECTION, 0, 0, 0, NULL);
    if (!additional || !collection ||
        !CertAddStoreToCollection(collection, additional, 0, 0) ||
        !CertAddStoreToCollection(collection, peer->hCertStore, 0, 0)) goto cleanup;
    if (config->crl_file[0]) {
        WCHAR crl_path[MAX_PATH];
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, config->crl_file,
                                 -1, crl_path, MAX_PATH) ||
            !CryptQueryObject(CERT_QUERY_OBJECT_FILE, crl_path,
                CERT_QUERY_CONTENT_FLAG_CRL, CERT_QUERY_FORMAT_FLAG_ALL, 0,
                NULL, NULL, NULL, NULL, NULL, (const void **)&crl) ||
            !CertAddCRLContextToStore(additional, crl, CERT_STORE_ADD_ALWAYS, NULL))
            goto cleanup;
    }
    if (config->ca_file[0]) {
        /* Private trust applies only to this connection, never LocalMachine Root. */
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, config->ca_file,
                                 -1, root_path, MAX_PATH)) goto cleanup;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, root_path,
                               CERT_QUERY_CONTENT_FLAG_CERT,
                               CERT_QUERY_FORMAT_FLAG_ALL, 0,
                               NULL, NULL, NULL, NULL, NULL,
                               (const void **)&root)) goto cleanup;
        roots = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        if (!roots || !CertAddCertificateContextToStore(roots, root,
                CERT_STORE_ADD_ALWAYS, NULL)) goto cleanup;
        memset(&engine_config, 0, sizeof(engine_config));
        engine_config.cbSize = sizeof(engine_config);
        engine_config.hExclusiveRoot = roots;
        engine_config.dwUrlRetrievalTimeout = config->timeout_ms;
        if (!CertCreateCertificateChainEngine(&engine_config, &engine)) goto cleanup;
    }
    memset(&parameters, 0, sizeof(parameters));
    parameters.cbSize = sizeof(parameters);
    parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;
    /* Strict offline policy: fresh cached revocation or an administrator-supplied
       signed CRL is required for every non-root certificate. Never soft-fail or
       fetch arbitrary certificate URLs from a privileged monitoring process. */
    if (!CertGetCertificateChain(engine ? engine : HCCE_LOCAL_MACHINE, peer,
            NULL, collection, &parameters,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL | CERT_CHAIN_DISABLE_AIA |
            CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE |
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY, NULL, &chain)) goto cleanup;
    /* A supplied stale/corrupt/revoking CRL must not be masked by cached evidence. */
    if (crl && !supplied_crl_valid(crl, chain)) {
        c->error = CRYPT_E_REVOCATION_OFFLINE;
        goto cleanup;
    }
    memset(&ssl_policy, 0, sizeof(ssl_policy));
    ssl_policy.cbSize = sizeof(ssl_policy);
    ssl_policy.dwAuthType = AUTHTYPE_SERVER;
    ssl_policy.pwszServerName = server_name;
    memset(&policy, 0, sizeof(policy));
    policy.cbSize = sizeof(policy);
    policy.pvExtraPolicyPara = &ssl_policy;
    memset(&status, 0, sizeof(status));
    status.cbSize = sizeof(status);
    ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
                                          &policy, &status) && !status.dwError;
cleanup:
    if (!ok && !c->error) c->error = status.dwError ? status.dwError : GetLastError();
    if (collection) CertCloseStore(collection, 0);
    if (additional) CertCloseStore(additional, 0);
    if (crl) CertFreeCRLContext(crl);
    if (chain) CertFreeCertificateChain(chain);
    if (engine) CertFreeCertificateChainEngine(engine);
    if (roots) CertCloseStore(roots, 0);
    if (root) CertFreeCertificateContext(root);
    if (peer) CertFreeCertificateContext(peer);
    return ok;
}

static int handshake(struct tls_connection *c, const char *name)
{
    BYTE *input = malloc(TLS_INPUT_SIZE);
    size_t used = 0;
    SECURITY_STATUS result = SEC_E_INTERNAL_ERROR;
    DWORD attributes;
    TimeStamp expiry;
    int first = 1, read_more = 0, ok = 0;
    if (!input) return 0;
    for (;;) {
        SecBuffer in_buffers[2], out_buffer;
        SecBufferDesc in_desc, out_desc;
        if (!active(c)) break;
        if (read_more) {
            int received;
            if (used == TLS_INPUT_SIZE || !wait_socket(c, 0)) break;
            received = recv(c->socket, (char *)input + used,
                             (int)(TLS_INPUT_SIZE - used), 0);
            if (received == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
                continue;
            if (received <= 0) {
                c->error = received ? (DWORD)WSAGetLastError() : WSAECONNRESET;
                break;
            }
            used += received;
        }
        memset(in_buffers, 0, sizeof(in_buffers));
        in_buffers[0].BufferType = SECBUFFER_TOKEN;
        in_buffers[0].pvBuffer = input;
        in_buffers[0].cbBuffer = (ULONG)used;
        in_buffers[1].BufferType = SECBUFFER_EMPTY;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 2;
        in_desc.pBuffers = in_buffers;
        memset(&out_buffer, 0, sizeof(out_buffer));
        out_buffer.BufferType = SECBUFFER_TOKEN;
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = &out_buffer;
        result = InitializeSecurityContextA(&c->credentials,
                first ? NULL : &c->context, (SEC_CHAR *)name, TLS_FLAGS, 0,
                SECURITY_NATIVE_DREP, first ? NULL : &in_desc, 0,
                &c->context, &out_desc, &attributes, &expiry);
        if (result != SEC_E_OK && result != SEC_I_CONTINUE_NEEDED &&
            result != SEC_E_INCOMPLETE_MESSAGE) c->error = (DWORD)result;
        if (result == SEC_E_OK || result == SEC_I_CONTINUE_NEEDED ||
            result == SEC_E_INCOMPLETE_MESSAGE || result == SEC_I_INCOMPLETE_CREDENTIALS)
            c->have_context = 1;
        first = 0;
        if (out_buffer.pvBuffer) {
            int sent = !out_buffer.cbBuffer || send_all(c, out_buffer.pvBuffer,
                                                       out_buffer.cbBuffer);
            FreeContextBuffer(out_buffer.pvBuffer);
            if (!sent) break;
        }
        if (result == SEC_E_OK) {
            ok = (attributes & ISC_RET_CONFIDENTIALITY) &&
                  (attributes & ISC_RET_STREAM);
            break;
        }
        if (result == SEC_E_INCOMPLETE_MESSAGE) {
            read_more = 1;
            continue;
        }
        /* Never continue anonymously if the configured client identity fails. */
        if (result != SEC_I_CONTINUE_NEEDED) break;
        if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
            size_t extra = in_buffers[1].cbBuffer;
            if (extra > used) break;
            memmove(input, input + used - extra, extra);
            used = extra;
        } else used = 0;
        read_more = used == 0;
    }
    free(input);
    return ok;
}

static int send_records(struct tls_connection *c, const char *message, size_t length)
{
    SecPkgContext_StreamSizes sizes;
    BYTE *record;
    size_t capacity;
    SECURITY_STATUS status = QueryContextAttributes(&c->context, SECPKG_ATTR_STREAM_SIZES,
                                                    &sizes);
    if (status != SEC_E_OK || !sizes.cbMaximumMessage) {
        c->error = status != SEC_E_OK ? (DWORD)status : ERROR_INVALID_DATA;
        return 0;
    }
    if (c->diagnostic) mrlog("TLS diagnostic: report bytes=%llu header=%lu trailer=%lu maximum=%lu",
        (unsigned long long)length, (unsigned long)sizes.cbHeader,
        (unsigned long)sizes.cbTrailer, (unsigned long)sizes.cbMaximumMessage);
    capacity = (size_t)sizes.cbHeader + sizes.cbMaximumMessage + sizes.cbTrailer;
    record = malloc(capacity);
    if (!record) { c->error = ERROR_NOT_ENOUGH_MEMORY; return 0; }
    while (length) {
        SecBuffer buffers[4];
        SecBufferDesc desc;
        size_t chunk = length > sizes.cbMaximumMessage ? sizes.cbMaximumMessage : length;
        memset(buffers, 0, sizeof(buffers));
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = record;
        buffers[0].cbBuffer = sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = record + sizes.cbHeader;
        buffers[1].cbBuffer = (ULONG)chunk;
        memcpy(buffers[1].pvBuffer, message, chunk);
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = record + sizes.cbHeader + chunk;
        buffers[2].cbBuffer = sizes.cbTrailer;
        buffers[3].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;
        {
            SECURITY_STATUS status = EncryptMessage(&c->context, 0, &desc, 0);
            if (status != SEC_E_OK) { c->error = (DWORD)status; goto failure; }
        }
        /* Schannel's stream buffers occupy this single contiguous record.
           Avoid delaying a tiny body/trailer behind Nagle's algorithm. */
        if (!send_all(c, record, (size_t)buffers[0].cbBuffer +
                      buffers[1].cbBuffer + buffers[2].cbBuffer)) goto failure;
        if (c->diagnostic) mrlog("TLS diagnostic: record queued plaintext=%llu encrypted=%lu/%lu/%lu",
            (unsigned long long)chunk, (unsigned long)buffers[0].cbBuffer,
            (unsigned long)buffers[1].cbBuffer, (unsigned long)buffers[2].cbBuffer);
        message += chunk;
        length -= chunk;
    }
    free(record);
    return 1;
failure:
    free(record);
    return 0;
}

static int close_notify(struct tls_connection *c, const char *name)
{
    DWORD shutdown_token = SCHANNEL_SHUTDOWN, attributes;
    SecBuffer token, output;
    SecBufferDesc control, response;
    TimeStamp expiry;
    SECURITY_STATUS status;
    int ok;
    memset(&token, 0, sizeof(token));
    token.BufferType = SECBUFFER_TOKEN;
    token.pvBuffer = &shutdown_token;
    token.cbBuffer = sizeof(shutdown_token);
    control.ulVersion = SECBUFFER_VERSION;
    control.cBuffers = 1;
    control.pBuffers = &token;
    status = ApplyControlToken(&c->context, &control);
    if (status != SEC_E_OK) { c->error = (DWORD)status; return 0; }
    memset(&output, 0, sizeof(output));
    output.BufferType = SECBUFFER_TOKEN;
    response.ulVersion = SECBUFFER_VERSION;
    response.cBuffers = 1;
    response.pBuffers = &output;
    status = InitializeSecurityContextA(&c->credentials, &c->context,
            (SEC_CHAR *)name, TLS_FLAGS, 0, SECURITY_NATIVE_DREP, NULL, 0,
            &c->context, &response, &attributes, &expiry);
    ok = status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED;
    if (!ok) c->error = (DWORD)status;
    if (output.pvBuffer) {
        if (ok) ok = send_all(c, output.pvBuffer, output.cbBuffer);
        FreeContextBuffer(output.pvBuffer);
    }
    return ok;
}

static int finish_socket(struct tls_connection *c)
{
    char discard[4096];
    unsigned long long received = 0;
    /* close_notify is queued, not a guarantee that TCP has delivered it.
       Half-close writes, then drain the peer's final TLS traffic before closing.
       Closing with unread session tickets can reset TCP and lose queued reports.
       No response is interpreted as an application acknowledgment. */
    if (shutdown(c->socket, SD_SEND) == SOCKET_ERROR) {
        c->error = (DWORD)WSAGetLastError();
        return 0;
    }
    while (active(c)) {
        int count;
        if (!wait_socket(c, 0)) return 0;
        count = recv(c->socket, discard, sizeof(discard), 0);
        if (count == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (!count) {
            if (c->diagnostic) mrlog("TLS diagnostic: peer EOF drained=%llu", received);
            return 1;
        }
        if (count == SOCKET_ERROR) {
            c->error = (DWORD)WSAGetLastError();
            return 0;
        }
        received += (unsigned int)count;
    }
    return 0;
}

int mr_tls_send(const struct sockaddr_in *address, const char *server_name,
                const char *bind_address, const struct mr_tls_config *config,
                const char *message, size_t length)
{
    struct tls_connection c;
    SCH_CREDENTIALS credentials;
    TLS_PARAMETERS protocols;
    PCCERT_CONTEXT client = NULL;
    struct sockaddr_in local;
    TimeStamp expiry;
    unsigned long nonblocking = 1;
    int error = 0, ok = 0;
    int error_size = sizeof(error);
    SECURITY_STATUS security_status;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
    DWORD key_spec = 0;
    BOOL free_key = FALSE;

    memset(&c, 0, sizeof(c));
    c.socket = INVALID_SOCKET;
    c.stage = "configuration";
    c.error = ERROR_INVALID_PARAMETER;
    c.diagnostic = config->diagnostic;
    if (config->invalid || !server_name[0] || !config->timeout_ms || config->timeout_ms > 60000 ||
        (config->ca_file[0] && !mr_tls_local_path(config->ca_file)) ||
        (config->crl_file[0] && !mr_tls_local_path(config->crl_file)))
        goto cleanup;
    c.deadline = GetTickCount64() + config->timeout_ms;
    if (config->report_deadline && config->report_deadline < c.deadline)
        c.deadline = config->report_deadline;
    if (!active(&c)) goto cleanup;
    c.stage = "client-certificate";
    client = client_certificate(config->client_thumbprint);
    if (!client) { c.error = CRYPT_E_NOT_FOUND; goto cleanup; }
    c.error = CERT_E_EXPIRED;
    if (CertVerifyTimeValidity(NULL, client->pCertInfo)) goto cleanup;
    c.error = 0;
    c.stage = "private-key-access";
    if (!CryptAcquireCertificatePrivateKey(client, CRYPT_ACQUIRE_SILENT_FLAG |
            CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG,
            NULL, &key, &key_spec, &free_key)) {
        c.error = GetLastError();
        goto cleanup;
    }
    memset(&credentials, 0, sizeof(credentials));
    credentials.dwVersion = SCH_CREDENTIALS_VERSION;
    credentials.cCreds = 1;
    credentials.paCred = &client;
    memset(&protocols, 0, sizeof(protocols));
    protocols.grbitDisabledProtocols = SP_PROT_SSL2 | SP_PROT_SSL3 |
                                       SP_PROT_TLS1_0 | SP_PROT_TLS1_1;
    credentials.cTlsParameters = 1;
    credentials.pTlsParameters = &protocols;
    credentials.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
                           SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO |
                           SCH_CRED_CACHE_ONLY_URL_RETRIEVAL;
    c.stage = "credentials";
    security_status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
            NULL, &credentials, NULL, NULL, &c.credentials, &expiry);
    if (security_status != SEC_E_OK) { c.error = (DWORD)security_status; goto cleanup; }
    c.have_credentials = 1;
    c.stage = "socket";
    c.socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c.socket == INVALID_SOCKET) { c.error = (DWORD)WSAGetLastError(); goto cleanup; }
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr(bind_address);
    if (bind(c.socket, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR ||
        ioctlsocket(c.socket, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        c.error = (DWORD)WSAGetLastError(); goto cleanup;
    }
    c.stage = "connect";
    if (connect(c.socket, (const struct sockaddr *)address, sizeof(*address)) == SOCKET_ERROR &&
        WSAGetLastError() != WSAEWOULDBLOCK) { c.error = (DWORD)WSAGetLastError(); goto cleanup; }
    if (!wait_socket(&c, 1) ||
        getsockopt(c.socket, SOL_SOCKET, SO_ERROR, (char *)&error, &error_size) || error)
        { if (error) c.error = (DWORD)error; goto cleanup; }
    c.stage = "handshake";
    if (!handshake(&c, server_name)) goto cleanup;
    if (!active(&c) || !verify_server(&c, server_name, config))
        goto cleanup;
    if (c.diagnostic) {
        SecPkgContext_ConnectionInfo info;
        if (QueryContextAttributes(&c.context, SECPKG_ATTR_CONNECTION_INFO, &info) == SEC_E_OK)
            mrlog("TLS diagnostic: authenticated protocol=0x%08lx cipher=0x%08lx bits=%lu",
                (unsigned long)info.dwProtocol, (unsigned long)info.aiCipher,
                (unsigned long)info.dwCipherStrength);
    }
    c.stage = "report-write";
    c.error = 0;
    if (send_records(&c, message, length)) {
        c.stage = "close-notify";
        ok = close_notify(&c, server_name);
        if (c.diagnostic) mrlog("TLS diagnostic: close-notify result=%d code=0x%08lx",
            ok, (unsigned long)c.error);
        if (ok) {
            c.stage = "tcp-drain";
            ok = finish_socket(&c);
        }
    }
cleanup:
    if (!ok) mrlog("TLS report to %s:%u (%s) failed: stage=%s code=0x%08lx; no plaintext fallback",
        inet_ntoa(address->sin_addr), (unsigned int)ntohs(address->sin_port),
        server_name, c.stage, (unsigned long)c.error);
    if (c.have_context) DeleteSecurityContext(&c.context);
    if (c.have_credentials) FreeCredentialsHandle(&c.credentials);
    if (free_key) {
        if (key_spec == CERT_NCRYPT_KEY_SPEC) NCryptFreeObject(key);
        else CryptReleaseContext(key, 0);
    }
    if (client) CertFreeCertificateContext(client);
    if (c.socket != INVALID_SOCKET) closesocket(c.socket);
    return ok;
}
