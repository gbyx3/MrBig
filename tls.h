#ifndef MRBIG_TLS_H
#define MRBIG_TLS_H

#include <winsock2.h>

/* Thumbprint identifies a certificate; it is not a server trust override. */
struct mr_tls_config {
    char client_thumbprint[41];
    char ca_file[MAX_PATH];
    char crl_file[MAX_PATH];
    DWORD timeout_ms;
    ULONGLONG report_deadline;
    int invalid;
};

/* One report per connection. Returns 0 on failure; never retries in plaintext. */
int mr_tls_send(const struct sockaddr_in *address, const char *server_name,
                const char *bind_address, const struct mr_tls_config *config,
                const char *message, size_t length);

/* Signal from the service-control thread; never clear while a send is active. */
void mr_tls_cancel(void);

#endif
