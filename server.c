#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>

static volatile int server_fd = -1;

static void handle_signal(int sig) {
    (void)sig;
    if (server_fd != -1)
        close(server_fd);
    _exit(0);
}

#define PORT 8080
#define BUFSIZE 4096

static void log_request(const char *ip, const char *tcp_ip,
                        const char *xff, const char *xri, int status) {
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    char xff_buf[256] = "", xri_buf[128] = "";
    if (xff) sscanf(xff, "%255[^\r\n]", xff_buf);
    if (xri) sscanf(xri, "%127[^\r\n]", xri_buf);

    fprintf(stderr,
        "{\"time\":\"%s\",\"ip\":\"%s\",\"tcp_ip\":\"%s\""
        "%s%s%s%s%s%s"
        ",\"status\":%d}\n",
        ts, ip, tcp_ip,
        xff ? ",\"x_forwarded_for\":\"" : "", xff ? xff_buf : "", xff ? "\"" : "",
        xri ? ",\"x_real_ip\":\""       : "", xri ? xri_buf : "", xri ? "\"" : "",
        status);
}

static const char *find_header(const char *buf, const char *name) {
    const char *p = buf;
    size_t name_len = strlen(name);
    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            p += name_len + 1;
            while (*p == ' ') p++;
            return p;
        }
    }
    return NULL;
}

static void send_status(int fd, int code, const char *text) {
    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s\n",
        code, text, strlen(text) + 1, text);
    send(fd, buf, len, 0);
    close(fd);
}

static void handle_client(int client_fd, const char *tcp_ip, const char *api_key) {
    char buf[BUFSIZE];
    ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buf[n] = '\0';

    const char *forwarded = find_header(buf, "X-Forwarded-For");
    const char *real_ip   = find_header(buf, "X-Real-IP");

    char ip[128];
    if (forwarded) {
        /* Take the last entry — nginx appends the real peer IP via
         * $proxy_add_x_forwarded_for so it cannot be spoofed by the client. */
        const char *last = forwarded;
        const char *p = forwarded;
        while ((p = strchr(p, ',')) != NULL) {
            p++;
            while (*p == ' ') p++;
            if (*p && *p != '\r' && *p != '\n')
                last = p;
        }
        sscanf(last, "%127[^,\r\n ]", ip);
    } else if (real_ip) {
        sscanf(real_ip, "%127[^\r\n]", ip);
    } else {
        snprintf(ip, sizeof(ip), "%s", tcp_ip);
    }

    char *end = ip + strlen(ip) - 1;
    while (end > ip && (*end == ' ' || *end == '\t')) *end-- = '\0';

    if (api_key) {
        const char *provided = find_header(buf, "X-API-Key");
        char key[256] = {0};
        if (provided)
            sscanf(provided, "%255[^\r\n]", key);
        if (!provided || strcmp(key, api_key) != 0) {
            log_request(ip, tcp_ip, forwarded, real_ip, 401);
            send_status(client_fd, 401, "Unauthorized");
            return;
        }
    }

    log_request(ip, tcp_ip, forwarded, real_ip, 200);
    send_status(client_fd, 200, ip);
}

int main(void) {
    const char *api_key = getenv("API_KEY");
    if (!api_key)
        fprintf(stderr, "Warning: API_KEY not set, running without authentication\n");

    struct sigaction sa = { .sa_handler = handle_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT),
    };

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(server_fd, 128) < 0) {
        perror("listen");
        return 1;
    }

    printf("Listening on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            break;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        handle_client(client_fd, client_ip, api_key);
    }

    close(server_fd);
    return 0;
}
