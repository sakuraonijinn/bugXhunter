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
#include <android/sensor.h>
#include <android/looper.h>

#define FRIDA_SERVER_PATH "/data/local/tmp/frida-server"
#define FRIDA_SERVER_PORT 27042
#define TUNNEL_LISTEN_PORT 7080
#define MAX_BUFFER 4096

// Adaptive policy loop - magnetometer monitoring via ASensorManager
void adaptive_policy_loop() {
    printf("Starting adaptive policy loop (magnetometer monitoring)...\n");
    
    ASensorManager *sensor_manager = ASensorManager_getInstance();
    const ASensor *magnetometer = ASensorManager_getDefaultSensor(sensor_manager, ASENSOR_TYPE_MAGNETIC_FIELD);
    
    if (magnetometer == NULL) {
        printf("No magnetometer available, using simulated readings\n");
    }
    
    ASensorEventQueue *queue = ASensorManager_createEventQueue(sensor_manager, ALooper_forThread(), 0, NULL, NULL);
    if (magnetometer != NULL && queue != NULL) {
        ASensorEventQueue_enableSensor(queue, magnetometer);
        ASensorEventQueue_setEventRate(queue, magnetometer, 100000); // 10Hz
    }
    
    while (1) {
        if (magnetometer != NULL && queue != NULL) {
            ASensorEvent event;
            if (ASensorEventQueue_getEvents(queue, &event, 1) > 0) {
                float x = event.magnetic.x;
                float y = event.magnetic.y;
                float z = event.magnetic.z;
                float magnitude = sqrt(x*x + y*y + z*z);
                
                printf("Magnetometer reading: %.2f uT\n", magnitude);
                
                if (magnitude > 50.0) {
                    printf("High magnetic field detected - adjusting transmission parameters\n");
                }
            }
        } else {
            // Fallback: no sensor available
            printf("Magnetometer unavailable - running in degraded mode\n");
        }
        
        sleep(1); // Check every second
    }
}

// Establish reverse tunnel to operator
int establish_reverse_tunnel(const char* operator_host, int operator_port) {
    // Try SSH reverse tunnel first
    if (access("/system/bin/ssh", X_OK) == 0) {
        printf("SSH available - attempting SSH reverse tunnel\n");
        
        // Fork and exec SSH with reverse tunnel
        pid_t ssh_pid = fork();
        if (ssh_pid == 0) {
            // Child: exec SSH
            char port_str[16];
            snprintf(port_str, sizeof(port_str), "%d", operator_port);
            char tunnel_spec[64];
            snprintf(tunnel_spec, sizeof(tunnel_spec), "%d:localhost:%d", operator_port, TUNNEL_LISTEN_PORT);
            
            execl("/system/bin/ssh", "ssh",
                  "-i", "/data/local/tmp/c2a_key",
                  "-o", "StrictHostKeyChecking=no",
                  "-o", "UserKnownHostsFile=/dev/null",
                  "-o", "ServerAliveInterval=30",
                  "-o", "ServerAliveCountMax=3",
                  "-N", "-R", tunnel_spec,
                  operator_host, NULL);
            perror("execl ssh failed");
            _exit(1);
        } else if (ssh_pid < 0) {
            perror("fork");
            // Fall through to raw TCP
        } else {
            // Parent: wait briefly to see if SSH connects
            sleep(2);
            int status;
            pid_t result = waitpid(ssh_pid, &status, WNOHANG);
            if (result == 0) {
                // SSH is still running - success
                printf("SSH reverse tunnel established (PID: %d)\n", ssh_pid);
                // SSH runs in background; we return a dummy socket
                // The caller should monitor the SSH process
                return ssh_pid > 0 ? ssh_pid : -1;
            } else {
                printf("SSH failed to connect, falling back to raw TCP\n");
            }
        }
    }
    
    // Raw TCP fallback
    printf("Using raw TCP tunnel\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(operator_port);
    inet_pton(AF_INET, operator_host, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }
    
    // PSK handshake
    unsigned char challenge[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    send(sock, challenge, 4, 0);
    
    unsigned char response[4];
    recv(sock, response, 4, 0);
    
    unsigned char expected[4] = {0xEF, 0xBE, 0xAD, 0xDE};
    if (memcmp(response, expected, 4) != 0) {
        printf("PSK handshake failed\n");
        close(sock);
        return -1;
    }
    
    printf("Raw TCP reverse tunnel established to operator\n");
    return sock;
}
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(operator_port);
    inet_pton(AF_INET, operator_host, &addr.sin_addr);
    
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

// Proxy loop: forward data between tunnel socket and local service
static void proxy_loop(int tunnel_sock, int local_port) {
    int local_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (local_sock < 0) {
        perror("socket");
        return;
    }
    
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    inet_pton(AF_INET, "127.0.0.1", &local_addr.sin_addr);
    
    if (connect(local_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("connect to local service");
        close(local_sock);
        return;
    }
    
    printf("Proxy loop started: tunnel <-> localhost:%d\n", local_port);
    
    fd_set read_fds;
    char buffer[MAX_BUFFER];
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(tunnel_sock, &read_fds);
        FD_SET(local_sock, &read_fds);
        
        int max_fd = tunnel_sock > local_sock ? tunnel_sock : local_sock;
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        
        if (activity < 0) {
            perror("select");
            break;
        }
        
        // Data from tunnel → local
        if (FD_ISSET(tunnel_sock, &read_fds)) {
            int bytes = recv(tunnel_sock, buffer, MAX_BUFFER, 0);
            if (bytes <= 0) {
                printf("Tunnel closed\n");
                break;
            }
            send(local_sock, buffer, bytes, 0);
        }
        
        // Data from local → tunnel
        if (FD_ISSET(local_sock, &read_fds)) {
            int bytes = recv(local_sock, buffer, MAX_BUFFER, 0);
            if (bytes <= 0) {
                printf("Local service closed\n");
                break;
            }
            send(tunnel_sock, buffer, bytes, 0);
        }
    }
    
    close(local_sock);
}
// Unified main loop: multiplex commands and proxy data via select()
void main_loop(int tunnel_sock) {
    unsigned char buffer[MAX_BUFFER];
    int local_sock = -1;
    
    // Try to connect to local service (port 7080) for proxying
    // Non-blocking: if local service isn't up yet, we just handle commands
    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(TUNNEL_LISTEN_PORT);
    inet_pton(AF_INET, "127.0.0.1", &local_addr.sin_addr);
    
    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(tunnel_sock, &read_fds);
        int max_fd = tunnel_sock;
        
        if (local_sock >= 0) {
            FD_SET(local_sock, &read_fds);
            if (local_sock > max_fd) max_fd = local_sock;
        }
        
        // Try connecting to local service if not connected
        if (local_sock < 0) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock >= 0) {
                // Non-blocking connect
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);
                connect(sock, (struct sockaddr*)&local_addr, sizeof(local_addr));
                // Check if connected
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(sock, &write_fds);
                struct timeval tv = {0, 100000}; // 100ms timeout
                if (select(sock + 1, NULL, &write_fds, NULL, &tv) > 0) {
                    int err = 0;
                    socklen_t len = sizeof(err);
                    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
                    if (err == 0) {
                        // Connected successfully
                        fcntl(sock, F_SETFL, flags); // Back to blocking
                        local_sock = sock;
                        printf("Connected to local service on port %d\n", TUNNEL_LISTEN_PORT);
                    } else {
                        close(sock);
                    }
                } else {
                    close(sock);
                }
            }
        }
        
        struct timeval timeout = {1, 0}; // 1 second timeout
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno == EINTR) continue;
            perror("select");
            break;
        }
        
        if (activity == 0) {
            // Timeout - continue loop
            continue;
        }
        
        // Data from tunnel
        if (FD_ISSET(tunnel_sock, &read_fds)) {
            int bytes = recv(tunnel_sock, buffer, MAX_BUFFER, 0);
            if (bytes <= 0) {
                printf("Tunnel closed\n");
                break;
            }
            
            // Check if it's a JSON command
            if (buffer[0] == '{') {
                char* cmd_str = (char*)buffer;
                if (bytes < MAX_BUFFER) cmd_str[bytes] = '\0';
                else cmd_str[MAX_BUFFER - 1] = '\0';
                
                if (strstr(cmd_str, "\"action\":\"START_FRIDA\"") || strstr(cmd_str, "\"action\": \"START_FRIDA\"")) {
                    printf("Command: START_FRIDA\n");
                    launch_frida_server();
                    send(tunnel_sock, "{\"status\":\"ok\"}", 13, 0);
                } else if (strstr(cmd_str, "\"action\":\"STOP_FRIDA\"") || strstr(cmd_str, "\"action\": \"STOP_FRIDA\"")) {
                    printf("Command: STOP_FRIDA\n");
                    system("pkill -x frida-server");
                    send(tunnel_sock, "{\"status\":\"ok\"}", 13, 0);
                } else if (strstr(cmd_str, "\"action\":\"KILL\"") || strstr(cmd_str, "\"action\": \"KILL\"")) {
                    printf("Command: KILL\n");
                    send(tunnel_sock, "{\"status\":\"ok\"}", 13, 0);
                    break;
                } else {
                    // Not a recognized command - forward to local service
                    if (local_sock >= 0) {
                        send(local_sock, buffer, bytes, 0);
                    }
                }
            } else {
                // Raw data - forward to local service
                if (local_sock >= 0) {
                    send(local_sock, buffer, bytes, 0);
                }
            }
        }
        
        // Data from local service
        if (local_sock >= 0 && FD_ISSET(local_sock, &read_fds)) {
            int bytes = recv(local_sock, buffer, MAX_BUFFER, 0);
            if (bytes <= 0) {
                printf("Local service closed\n");
                close(local_sock);
                local_sock = -1;
            } else {
                send(tunnel_sock, buffer, bytes, 0);
            }
        }
    }
    
    if (local_sock >= 0) close(local_sock);
}
    unsigned char buffer[MAX_BUFFER];
    
    while (1) {
        int bytes = recv(tunnel_sock, buffer, MAX_BUFFER, 0);
        if (bytes <= 0) {
            break;
        }
        
        // Parse JSON command
        // {"action": "START_FRIDA|STOP_FRIDA|ROTATE_PSK|KILL|WIPE", "target": "pkg.name"}
        char* cmd_str = (char*)buffer;
        if (bytes < MAX_BUFFER) {
            cmd_str[bytes] = '\0';
        } else {
            cmd_str[MAX_BUFFER - 1] = '\0';
        }
        
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
    const char* operator_host = "127.0.0.1";
    int operator_port = 9090;
    
    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--operator-host") == 0 && i + 1 < argc) {
            operator_host = argv[++i];
        } else if (strcmp(argv[i], "--operator-port") == 0 && i + 1 < argc) {
            operator_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--frida-path") == 0 && i + 1 < argc) {
            // Allow overriding frida server path via env
            setenv("FRIDA_SERVER_PATH", argv[++i], 1);
        }
    }
    
    printf("BugXhunter Bootstrapper starting...\n");
    printf("Architecture: %s\n", sizeof(void*) == 8 ? "arm64" : "arm");
    printf("Operator: %s:%d\n", operator_host, operator_port);
    
    // 1. Launch frida-server
    pid_t frida_pid = launch_frida_server();
    if (frida_pid < 0) {
        fprintf(stderr, "Failed to launch frida-server\n");
        return 1;
    }
    
    // 2. Establish reverse tunnel
    int tunnel_sock = establish_reverse_tunnel(operator_host, operator_port);
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
    
    // 4. Main loop: multiplex commands and proxy data
    main_loop(tunnel_sock);
    
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
