#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include <lwip/netdb.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>

// Use hardware TRNG

extern int bl_rand();

int mbedtls_hardware_poll(void *data,
    unsigned char *output, size_t len, size_t *olen)
{
    printf("Hardware entropy poll called!\r\n");

    ((void) data);
    size_t i;
    *olen = 0;
    unsigned int rand_buf = 0;

    for (i = 0; i < len; i++) {
        if (0 == (i % 4)) {
            rand_buf = bl_rand();
        }
        output[i] = rand_buf & 0xFF;
        rand_buf = rand_buf >> 8;
    }

    *olen = len;

    return 0;
}

// Networking code

#define MBEDTLS_NET_PRINT(_f, ...)  \
            printf("%s %d: "_f,  __FUNCTION__, __LINE__, ##__VA_ARGS__)

// Initializing the context
void mbedtls_net_init(mbedtls_net_context *ctx)
{
    ctx->fd = -1;
}

// Initiate a TCP connection with host:port and the given protocol
int mbedtls_net_connect(mbedtls_net_context *ctx, const char *host,
    const char *port, int proto)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    struct addrinfo hints, *addr_list, *cur;

    // Name resolution with IPv4 and IPv6
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &addr_list) != 0) {
        MBEDTLS_NET_PRINT("getaddrinfo fail- errno: %d\n", errno);
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;
    }

    // Try the socket addres until a connection succeets
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;

    for (cur=addr_list; cur != NULL; cur = cur->ai_next) {
        ctx->fd = (int) socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (ctx->fd < 0) {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if (connect(ctx->fd, cur->ai_addr, (int) cur->ai_addrlen) == 0) {
            ret = 0;
            break;
        }
        mbedtls_net_close(ctx);
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
    }
    freeaddrinfo(addr_list);
    return ret;
}

// Set the socket blocking or non-blocking
int mbedtls_net_set_block(mbedtls_net_context *ctx)
{
    int flags = fcntl(ctx->fd, F_GETFL, 0);
    flags &= ~O_NONBLOCK;
    return fcntl(ctx->fd, F_SETFL, flags);
}

int mbedtls_net_set_nonblock(mbedtls_net_context *ctx)
{
    int flags = fcntl(ctx->fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    return fcntl(ctx->fd, F_SETFL, flags);
}

// Read at most 'len' characters, blocking for at most 'timeout' ms
int mbedtls_net_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                             uint32_t timeout )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    struct timeval tv;
    fd_set read_fds;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if (fd < 0) {
        return MBEDTLS_ERR_NET_INVALID_CONTEXT;
    }

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    tv.tv_sec  = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    ret = select(fd + 1, &read_fds, NULL, NULL, timeout == 0 ? NULL : &tv);

    // Zero FDs ready means we timed out
    if (ret == 0) {
        return MBEDTLS_ERR_SSL_TIMEOUT;
    }

    if (ret < 0) {
        if (errno == EINTR) {
            return MBEDTLS_ERR_SSL_WANT_READ;
        }

        return MBEDTLS_ERR_NET_RECV_FAILED;
    }

    // This call will not block
    return mbedtls_net_recv(ctx, buf, len);
}

// Check if the requested operation would be blocking on a non-blocking socket
// and thus 'failed with a negative return value.

static int net_would_block(const mbedtls_net_context *ctx)
{
    /*
     * Never return 'WOULD BLOCK' on a non-blocking socket
     */
    if ((fcntl(ctx->fd, F_GETFL, 0) & O_NONBLOCK) != O_NONBLOCK) {
        return 0;
    }
    
    switch (errno) {
#if defined EAGAIN
        case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK:
#endif
            return 1;
    }

    return 0;
}

// Write at most 'len' characters
int mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if (fd < 0) {
        return (MBEDTLS_ERR_NET_INVALID_CONTEXT);
    }

    ret = (int)write(fd, buf, len);

    if (ret < 0) {
        if (net_would_block(ctx) != 0) {
            return (MBEDTLS_ERR_SSL_WANT_WRITE);
        }

        if (errno == EPIPE || errno == ECONNRESET) {
            MBEDTLS_NET_PRINT("net reset - errno: %d\n", errno);
            return (MBEDTLS_ERR_NET_CONN_RESET);
        }

        if (errno == EINTR) {
            return (MBEDTLS_ERR_SSL_WANT_WRITE);
        }

        MBEDTLS_NET_PRINT("net send failed - errno: %d\n", errno);
        return (MBEDTLS_ERR_NET_SEND_FAILED);
    }

    return ret;
}

// Read at most 'len' characters
int mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if (fd < 0) {
        MBEDTLS_NET_PRINT("invalid socket fd\n");
        return (MBEDTLS_ERR_NET_INVALID_CONTEXT);
    }

    ret = (int)read(fd, buf, len);

    if (ret < 0) {
        if (net_would_block(ctx) != 0) {
            return (MBEDTLS_ERR_SSL_WANT_READ);
        }

        if (errno == EPIPE || errno == ECONNRESET) {
            MBEDTLS_NET_PRINT("net reset - errno: %d\n", errno);
            return (MBEDTLS_ERR_NET_CONN_RESET);
        }

        if (errno == EINTR) {
            return (MBEDTLS_ERR_SSL_WANT_READ);
        }

        MBEDTLS_NET_PRINT("net recv failed - errno: %d\n", errno);
        return (MBEDTLS_ERR_NET_RECV_FAILED);
    }

    return ret;
}

// Close the connection
void mbedtls_net_terminate(mbedtls_net_context *ctx, bool shutdown)
{
    if (ctx->fd == -1) {
        return;
    }

    if (shutdown) {
        shutdown(ctx->fd, 2);
    }

    close(ctx->fd);
    ctx->fd = -1;
}

void mbedtls_net_close(mbedtls_net_context *ctx)
{
    mbedtls_net_terminate(ctx, false); 
}

void mbedtls_net_free(mbedtls_net_context *ctx)
{
    mbedtls_net_terminate(ctx, true);
}