/* Isolated transport test executable; never installs a service. */
#include "tls.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

void mrlog(char *format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
}

int main(int argc, char **argv)
{
    struct mr_tls_config config;
    struct sockaddr_in address;
    WSADATA data;
    char message[65536];
    int result;
    if (argc != 6 || strlen(argv[3]) >= sizeof(config.client_thumbprint) ||
        strlen(argv[4]) >= sizeof(config.ca_file)) return 2;
    memset(&config, 0, sizeof(config));
    strcpy(config.client_thumbprint, argv[3]);
    strcpy(config.ca_file, argv[4]);
    config.timeout_ms = (DWORD)strtoul(argv[5], NULL, 10);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons((unsigned short)atoi(argv[1]));
    memset(message, 'x', sizeof(message));
    if (WSAStartup(MAKEWORD(2, 2), &data)) return 2;
    result = mr_tls_send(&address, argv[2], "127.0.0.1", &config,
                         message, sizeof(message));
    WSACleanup();
    return result ? 0 : 1;
}
