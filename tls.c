/* Native Windows transport. No OpenSSL dependency or private-key export. */
#define _WIN32_WINNT 0x0601
#define SECURITY_WIN32
#include <winsock2.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "tls.h"

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
};

static int wait_socket(struct tls_connection *c, int writing)
{
    fd_set ready, errors;
    struct timeval timeout;
    ULONGLONG now = GetTickCount64(), remaining;
    int result;
    if (now >= c->deadline) return 0;
    remaining = c->deadline - now;
    timeout.tv_sec = (long)(remaining / 1000);
    timeout.tv_usec = (long)((remaining % 1000) * 1000);
    FD_ZERO(&ready);
    FD_ZERO(&errors);
    FD_SET(c->socket, &ready);
    FD_SET(c->socket, &errors);
    result = select(0, writing ? NULL : &ready, writing ? &ready : NULL,
                    &errors, &timeout);
    return result > 0 && !FD_ISSET(c->socket, &errors);
}

static int send_all(struct tls_connection *c, const void *data, size_t length)
{
    const char *p = data;
    while (length) {
        int sent;
        if (!wait_socket(c, 1)) return 0;
        sent = send(c->socket, p, (int)(length > INT_MAX ? INT_MAX : length), 0);
        if (sent == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        if (sent <= 0) return 0;
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

static int verify_server(struct tls_connection *c, const char *name,
                         const struct mr_tls_config *config)
{
    PCCERT_CONTEXT peer = NULL, root = NULL;
    PCCERT_CHAIN_CONTEXT chain = NULL;
    HCERTSTORE roots = NULL;
    HCERTCHAINENGINE engine = NULL;
    CERT_CHAIN_ENGINE_CONFIG engine_config;
    CERT_CHAIN_PARA parameters;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl_policy;
    CERT_CHAIN_POLICY_PARA policy;
    CERT_CHAIN_POLICY_STATUS status;
    WCHAR server_name[256], root_path[MAX_PATH];
    LPSTR usage = szOID_PKIX_KP_SERVER_AUTH;
    int ok = 0;

    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1,
                             server_name, 256)) goto cleanup;
    if (QueryContextAttributes(&c->context, SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                               &peer) != SEC_E_OK) goto cleanup;
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
    /* No network retrieval during validation; cached intermediates are permitted.
       Revocation policy is a follow-up before production acceptance. */
    if (!CertGetCertificateChain(engine ? engine : HCCE_LOCAL_MACHINE, peer,
            NULL, peer->hCertStore, &parameters,
            CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &chain)) goto cleanup;
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
    SECURITY_STATUS result;
    DWORD attributes;
    TimeStamp expiry;
    int first = 1, read_more = 0, ok = 0;
    if (!input) return 0;
    for (;;) {
        SecBuffer in_buffers[2], out_buffer;
        SecBufferDesc in_desc, out_desc;
        if (GetTickCount64() >= c->deadline) break;
        if (read_more) {
            int received;
            if (used == TLS_INPUT_SIZE || !wait_socket(c, 0)) break;
            received = recv(c->socket, (char *)input + used,
                             (int)(TLS_INPUT_SIZE - used), 0);
            if (received == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)
                continue;
            if (received <= 0) break;
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
    if (QueryContextAttributes(&c->context, SECPKG_ATTR_STREAM_SIZES,
                               &sizes) != SEC_E_OK || !sizes.cbMaximumMessage)
        return 0;
    capacity = (size_t)sizes.cbHeader + sizes.cbMaximumMessage + sizes.cbTrailer;
    record = malloc(capacity);
    if (!record) return 0;
    while (length) {
        SecBuffer buffers[4];
        SecBufferDesc desc;
        size_t chunk = length > sizes.cbMaximumMessage ? sizes.cbMaximumMessage : length;
        unsigned int i;
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
        if (EncryptMessage(&c->context, 0, &desc, 0) != SEC_E_OK) goto failure;
        for (i = 0; i < 3; ++i)
            if (!send_all(c, buffers[i].pvBuffer, buffers[i].cbBuffer)) goto failure;
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
    if (ApplyControlToken(&c->context, &control) != SEC_E_OK) return 0;
    memset(&output, 0, sizeof(output));
    output.BufferType = SECBUFFER_TOKEN;
    response.ulVersion = SECBUFFER_VERSION;
    response.cBuffers = 1;
    response.pBuffers = &output;
    status = InitializeSecurityContextA(&c->credentials, &c->context,
            (SEC_CHAR *)name, TLS_FLAGS, 0, SECURITY_NATIVE_DREP, NULL, 0,
            &c->context, &response, &attributes, &expiry);
    ok = status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED;
    if (output.pvBuffer) {
        if (ok) ok = send_all(c, output.pvBuffer, output.cbBuffer);
        FreeContextBuffer(output.pvBuffer);
    }
    return ok;
}

int mr_tls_send(const struct sockaddr_in *address, const char *server_name,
                const char *bind_address, const struct mr_tls_config *config,
                const char *message, size_t length)
{
    struct tls_connection c;
    SCHANNEL_CRED credentials;
    PCCERT_CONTEXT client = NULL;
    struct sockaddr_in local;
    TimeStamp expiry;
    unsigned long nonblocking = 1;
    int error = 0, ok = 0;
    int error_size = sizeof(error);

    memset(&c, 0, sizeof(c));
    c.socket = INVALID_SOCKET;
    if (!server_name[0] || !config->timeout_ms || config->timeout_ms > 60000)
        goto cleanup;
    c.deadline = GetTickCount64() + config->timeout_ms;
    client = client_certificate(config->client_thumbprint);
    if (!client) goto cleanup;
    memset(&credentials, 0, sizeof(credentials));
    credentials.dwVersion = SCHANNEL_CRED_VERSION;
    credentials.cCreds = 1;
    credentials.paCred = &client;
    credentials.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    credentials.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION |
                           SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
    if (AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND,
            NULL, &credentials, NULL, NULL, &c.credentials, &expiry) != SEC_E_OK)
        goto cleanup;
    c.have_credentials = 1;
    c.socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c.socket == INVALID_SOCKET) goto cleanup;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = inet_addr(bind_address);
    if (bind(c.socket, (struct sockaddr *)&local, sizeof(local)) == SOCKET_ERROR ||
        ioctlsocket(c.socket, FIONBIO, &nonblocking) == SOCKET_ERROR) goto cleanup;
    if (connect(c.socket, (const struct sockaddr *)address, sizeof(*address)) == SOCKET_ERROR &&
        WSAGetLastError() != WSAEWOULDBLOCK) goto cleanup;
    if (!wait_socket(&c, 1) ||
        getsockopt(c.socket, SOL_SOCKET, SO_ERROR, (char *)&error, &error_size) || error)
        goto cleanup;
    if (!handshake(&c, server_name) || !verify_server(&c, server_name, config))
        goto cleanup;
    ok = send_records(&c, message, length) && close_notify(&c, server_name);
cleanup:
    if (!ok) mrlog("TLS report failed (no plaintext fallback)");
    if (c.have_context) DeleteSecurityContext(&c.context);
    if (c.have_credentials) FreeCredentialsHandle(&c.credentials);
    if (client) CertFreeCertificateContext(client);
    if (c.socket != INVALID_SOCKET) closesocket(c.socket);
    return ok;
}
