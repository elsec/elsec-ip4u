#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

static volatile int server_fd = -1;

static void handle_signal(int sig) {
    (void)sig;
    if (server_fd != -1)
        close(server_fd);
    _exit(0);
}

#define PORT 8080
#define BUFSIZE 4096

static void json_escape(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dst_size; i++) {
        if (src[i] == '"' || src[i] == '\\') dst[j++] = '\\';
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

static void log_request(const char *ip, const char *tcp_ip,
                        const char *xff, const char *xri,
                        const char *path, const char *client_id,
                        const char *cf_country, int status) {
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    char xff_raw[256] = "", xri_raw[128] = "", country_raw[8] = "";
    if (xff) sscanf(xff, "%255[^\r\n]", xff_raw);
    if (xri) sscanf(xri, "%127[^\r\n]", xri_raw);
    if (cf_country) sscanf(cf_country, "%7[^\r\n]", country_raw);

    char ip_e[256], tcp_e[256], path_e[2048], xff_e[512], xri_e[256], cid_e[256], country_e[16];
    json_escape(ip,          ip_e,      sizeof(ip_e));
    json_escape(tcp_ip,      tcp_e,     sizeof(tcp_e));
    json_escape(path,        path_e,    sizeof(path_e));
    json_escape(xff_raw,     xff_e,     sizeof(xff_e));
    json_escape(xri_raw,     xri_e,     sizeof(xri_e));
    json_escape(client_id ? client_id : "", cid_e, sizeof(cid_e));
    json_escape(country_raw, country_e, sizeof(country_e));

    fprintf(stdout,
        "{\"time\":\"%s\",\"ip\":\"%s\",\"tcp_ip\":\"%s\""
        ",\"path\":\"%s\""
        "%s%s%s%s%s%s"
        "%s%s%s"
        "%s%s%s"
        ",\"status\":%d}\n",
        ts, ip_e, tcp_e, path_e,
        xff ? ",\"x_forwarded_for\":\"" : "", xff ? xff_e : "", xff ? "\"" : "",
        xri ? ",\"x_real_ip\":\""       : "", xri ? xri_e : "", xri ? "\"" : "",
        client_id  ? ",\"client_id\":\""  : "", client_id  ? cid_e     : "", client_id  ? "\"" : "",
        cf_country ? ",\"cf_country\":\"" : "", cf_country ? country_e : "", cf_country ? "\"" : "",
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

static void handle_client(int client_fd, const char *tcp_ip,
                          const char *secret_key, int cloudflare) {
    char buf[BUFSIZE];
    ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buf[n] = '\0';

    char path[1024] = "-";
    sscanf(buf, "%*s %1023s", path);

    const char *cf_connecting_ip = cloudflare ? find_header(buf, "CF-Connecting-IP") : NULL;
    const char *cf_country       = cloudflare ? find_header(buf, "CF-IPCountry")      : NULL;
    const char *forwarded        = find_header(buf, "X-Forwarded-For");
    const char *real_ip          = find_header(buf, "X-Real-IP");

    char ip[128];
    if (cf_connecting_ip) {
        sscanf(cf_connecting_ip, "%127[^\r\n]", ip);
    } else if (forwarded) {
        sscanf(forwarded, "%127[^,\r\n ]", ip);
    } else if (real_ip) {
        sscanf(real_ip, "%127[^\r\n]", ip);
    } else {
        snprintf(ip, sizeof(ip), "%s", tcp_ip);
    }

    char *end = ip + strlen(ip) - 1;
    while (end > ip && (*end == ' ' || *end == '\t')) *end-- = '\0';

    if (strcmp(path, "/") != 0) {
        log_request(ip, tcp_ip, forwarded, real_ip, path, NULL, cf_country, 401);
        send_status(client_fd, 401, "Unauthorized");
        return;
    }

    char key_buf[512] = {0};
    char *client_id = NULL;
    if (secret_key) {
        const char *provided = find_header(buf, "X-Client-Key");
        if (provided)
            sscanf(provided, "%511[^\r\n]", key_buf);

        char *colon = strchr(key_buf, ':');
        if (!colon) {
            log_request(ip, tcp_ip, forwarded, real_ip, path, NULL, cf_country, 401);
            send_status(client_fd, 401, "Unauthorized");
            return;
        }
        *colon = '\0';
        client_id = key_buf;
        const char *provided_hmac = colon + 1;

        unsigned char digest[32];
        unsigned int digest_len = sizeof(digest);
        HMAC(EVP_sha256(),
             secret_key, (int)strlen(secret_key),
             (unsigned char *)client_id, strlen(client_id),
             digest, &digest_len);

        char computed_hex[65];
        for (int i = 0; i < 32; i++)
            sprintf(computed_hex + i * 2, "%02x", digest[i]);
        computed_hex[64] = '\0';

        if (strlen(provided_hmac) != 64 ||
            CRYPTO_memcmp(computed_hex, provided_hmac, 64) != 0) {
            log_request(ip, tcp_ip, forwarded, real_ip, path, NULL, cf_country, 401);
            send_status(client_fd, 401, "Unauthorized");
            return;
        }
    }

    log_request(ip, tcp_ip, forwarded, real_ip, path, client_id, cf_country, 200);
    send_status(client_fd, 200, ip);
}

int main(int argc, char *argv[]) {
    int cloudflare = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--cloudflare") == 0)
            cloudflare = 1;
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    const char *secret_key = getenv("SECRET_KEY");
    if (!secret_key)
        fprintf(stderr, "Warning: SECRET_KEY not set, running without authentication\n");
    if (cloudflare)
        fprintf(stderr, "Cloudflare mode enabled: using CF-Connecting-IP\n");

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

        handle_client(client_fd, client_ip, secret_key, cloudflare);
    }

    close(server_fd);
    return 0;
}
