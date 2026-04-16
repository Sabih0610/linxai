/* executor/pam/pam_linxai_face.c
 *
 * PAM module that intercepts sudo authentication and delegates
 * to the LINxAI face authentication server over a Unix domain socket.
 *
 * Install:
 *   gcc -shared -fPIC -o pam_linxai_face.so pam_linxai_face.c \
 *       -lpam -lpam_misc
 *   sudo cp pam_linxai_face.so /lib/x86_64-linux-gnu/security/
 *
 * Configure /etc/pam.d/sudo — add as FIRST auth line:
 *   auth sufficient pam_linxai_face.so
 *
 * Protocol with Python server:
 *   Send: 4-byte big-endian length + JSON request bytes
 *   Recv: 4-byte big-endian length + JSON response bytes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define SOCKET_PATH   "/tmp/linxai_pam.sock"
#define BUF_SIZE      1024
#define TIMEOUT_SECS  12

/* Send exactly n bytes to socket fd */
static int send_all(int fd, const char *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = write(fd, buf + sent, n - sent);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

/* Receive exactly n bytes from socket fd */
static int recv_all(int fd, char *buf, size_t n) {
    size_t recvd = 0;
    while (recvd < n) {
        ssize_t r = read(fd, buf + recvd, n - recvd);
        if (r <= 0) return -1;
        recvd += r;
    }
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *user = NULL;
    pam_get_user(pamh, &user, NULL);
    if (!user) user = "unknown";

    /* Connect to face auth server */
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        pam_syslog(pamh, LOG_ERR, "LINxAI PAM: socket() failed: %s", strerror(errno));
        return PAM_AUTH_ERR;
    }

    /* Set socket timeout */
    struct timeval tv = { .tv_sec = TIMEOUT_SECS, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "LINxAI PAM: cannot connect to face auth server at %s: %s",
                   SOCKET_PATH, strerror(errno));
        close(sock);
        return PAM_AUTH_ERR;
    }

    /* Build JSON request */
    char request[BUF_SIZE];
    int req_len = snprintf(request, sizeof(request),
                           "{\"action\":\"authenticate\",\"user\":\"%s\"}", user);

    /* Send length-prefixed request */
    uint32_t net_len = htonl((uint32_t)req_len);
    if (send_all(sock, (char *)&net_len, 4) < 0 ||
        send_all(sock, request, req_len) < 0) {
        pam_syslog(pamh, LOG_ERR, "LINxAI PAM: send failed");
        close(sock);
        return PAM_AUTH_ERR;
    }

    /* Receive length-prefixed response */
    uint32_t resp_net_len;
    if (recv_all(sock, (char *)&resp_net_len, 4) < 0) {
        pam_syslog(pamh, LOG_ERR, "LINxAI PAM: recv length failed");
        close(sock);
        return PAM_AUTH_ERR;
    }

    uint32_t resp_len = ntohl(resp_net_len);
    if (resp_len >= BUF_SIZE) {
        pam_syslog(pamh, LOG_ERR, "LINxAI PAM: response too large: %u", resp_len);
        close(sock);
        return PAM_AUTH_ERR;
    }

    char response[BUF_SIZE];
    memset(response, 0, sizeof(response));
    if (recv_all(sock, response, resp_len) < 0) {
        pam_syslog(pamh, LOG_ERR, "LINxAI PAM: recv response failed");
        close(sock);
        return PAM_AUTH_ERR;
    }
    close(sock);

    /* Parse "success": true/false from JSON response (simple string search) */
    if (strstr(response, "\"success\": true") != NULL ||
        strstr(response, "\"success\":true")  != NULL) {
        pam_syslog(pamh, LOG_INFO, "LINxAI PAM: face auth GRANTED for user %s", user);
        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_WARNING, "LINxAI PAM: face auth DENIED for user %s", user);
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                               int argc, const char **argv) {
    return PAM_SUCCESS;
}