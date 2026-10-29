#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/sha.h>

#define SHA256_HEX_LEN 64

/* Download the frida-server binary via raw TCP socket.
 * Returns 0 on success, -1 on failure. */
int download_frida_server(const char *host, const char *port,
                          const char *psk, const char *expected_sha256) {
    int sock = -1;
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        return -1;
    }

    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        perror("socket creation failed");
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect failed");
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    char request[512];
    snprintf(request, sizeof(request),
             "GET /frida-server/arm64 HTTP/1.1\r\n"
             "Host: %s:%s\r\n"
             "X-Auth-Token: %s\r\n"
             "Connection: close\r\n"
             "\r\n",
             host, port, psk);

    if (send(sock, request, strlen(request), 0) < 0) {
        perror("send request failed");
        close(sock);
        return -1;
    }

    unsigned char buffer[8192];
    size_t bytes_read = 0;
    ssize_t n;
    while ((n = read(sock, buffer + bytes_read, sizeof(buffer) - bytes_read)) > 0) {
        bytes_read += (size_t)n;
        if (bytes_read >= sizeof(buffer)) break;
    }
    close(sock);

    if (n < 0) {
        perror("read failed");
        return -1;
    }

    /* Verify SHA-256 of the downloaded body against expected. */
    unsigned char computed[SHA256_DIGEST_LENGTH];
    SHA256(buffer, bytes_read, computed);

    char hex[SHA256_HEX_LEN + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(hex + i * 2, 3, "%02x", computed[i]);
    }
    hex[SHA256_HEX_LEN] = '\0';

    if (strcmp(hex, expected_sha256) != 0) {
        fprintf(stderr, "SHA-256 mismatch! Expected: %s, Got: %s\n",
                expected_sha256, hex);
        return -1;
    }

    /* Write verified payload to disk. */
    FILE *f = fopen("/data/local/tmp/frida-server", "wb");
    if (!f) {
        perror("fopen failed");
        return -1;
    }
    fwrite(buffer, 1, bytes_read, f);
    fclose(f);
    chmod("/data/local/tmp/frida-server", 0755);

    return 0;
}

int main(int argc, char *argv[]) {
    const char *host = "127.0.0.1";
    const char *port = "7080";
    const char *psk = NULL;
    const char *expected_sha256 = NULL;

    if (argc > 1) host = argv[1];
    if (argc > 2) port = argv[2];
    if (argc > 3) psk = argv[3];
    if (argc > 4) expected_sha256 = argv[4];

    if (!psk || !expected_sha256) {
        fprintf(stderr, "PSK and expected SHA-256 are required for download\n");
        return 1;
    }

    if (download_frida_server(host, port, psk, expected_sha256) == 0) {
        printf("Frida server downloaded successfully\n");
        return 0;
    }
    fprintf(stderr, "Failed to download frida server\n");
    return 1;
}
