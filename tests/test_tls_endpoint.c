#include "tls_endpoint.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char address[16], name[254];
    unsigned short port;
    const char *bad[] = {
        "", "proxy.example:1985 proxy.example", "127.0.0.1 proxy.example",
        "127.0.0.1:0 proxy.example", "127.0.0.1:65536 proxy.example",
        "127.0.0.1:-1 proxy.example", "127.0.0.1:1985",
        "127.0.0.1:1985 proxy.example extra", "256.0.0.1:1985 proxy.example",
        "127.00.0.1:1985 proxy.example", "127.1:1985 proxy.example",
        "127.0.0.1:1985 *.example", "127.0.0.1:1985 -proxy.example",
        "127.0.0.1:1985 proxy-.example", "127.0.0.1:1985 proxy..example",
        "127.0.0.1:1985 proxy.example.", "[::1]:1985 proxy.example",
        "127.0.0.1:1985 proxy_example", NULL
    };
    int i;
    assert(mr_tls_endpoint("127.0.0.1:1985 proxy.example", address, &port,
                           name, sizeof(name)));
    assert(!strcmp(address, "127.0.0.1") && port == 1985 &&
            !strcmp(name, "proxy.example"));
    assert(mr_tls_endpoint("192.0.2.1:65535 proxy-1.example  ", address,
                           &port, name, sizeof(name)));
    for (i = 0; bad[i]; ++i) {
        strcpy(address, "unchanged");
        strcpy(name, "unchanged");
        port = 42;
        assert(!mr_tls_endpoint(bad[i], address, &port, name, sizeof(name)));
        assert(!strcmp(address, "unchanged") && !strcmp(name, "unchanged") && port == 42);
    }
    assert(!mr_tls_endpoint("127.0.0.1:1985 proxy.example", address, &port, name, 5));
    puts("TLS endpoint parser tests passed");
    return 0;
}
