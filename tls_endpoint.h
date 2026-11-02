#ifndef MRBIG_TLS_ENDPOINT_H
#define MRBIG_TLS_ENDPOINT_H
#include <stddef.h>

/* Strict numeric IPv4:port plus DNS verification name. No implicit defaults. */
int mr_tls_endpoint(const char *value, char address[16], unsigned short *port,
                     char *name, size_t name_size);
#endif
