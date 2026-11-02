#include "tls_endpoint.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int alnum_ascii(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

int mr_tls_endpoint(const char *value, char address[16], unsigned short *port,
                     char *name, size_t name_size)
{
    char ip[16], number[6], host[254], extra;
    unsigned int octets[4];
    unsigned long parsed_port;
    size_t i, label = 0, length;
    if (sscanf(value, "%15[0-9.]:%5[0-9] %253s %c", ip, number, host, &extra) != 3)
        return 0;
    if (sscanf(ip, "%u.%u.%u.%u%c", &octets[0], &octets[1], &octets[2],
               &octets[3], &extra) != 4) return 0;
    for (i = 0; i < 4; ++i) if (octets[i] > 255) return 0;
    /* inet_addr treats some leading-zero forms as octal; require canonical IPv4. */
    {
        char canonical[16];
        snprintf(canonical, sizeof(canonical), "%u.%u.%u.%u", octets[0],
                  octets[1], octets[2], octets[3]);
        if (strcmp(canonical, ip)) return 0;
    }
    parsed_port = strtoul(number, NULL, 10);
    if (!parsed_port || parsed_port > 65535) return 0;
    length = strlen(host);
    if (!length || length >= name_size) return 0;
    for (i = 0; i < length; ++i) {
        if (host[i] == '.') {
            if (!label || host[i - 1] == '-') return 0;
            label = 0;
        } else {
            if (!alnum_ascii(host[i]) && host[i] != '-') return 0;
            if (!label && host[i] == '-') return 0;
            if (++label > 63) return 0;
        }
    }
    if (!label || host[length - 1] == '-') return 0;
    strcpy(address, ip);
    strcpy(name, host);
    *port = (unsigned short)parsed_port;
    return 1;
}
