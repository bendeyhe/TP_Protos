/**
 * main.c - servidor SMTP concurrente
 *
 * Interpreta los argumentos de línea de comandos, y monta un socket
 * pasivo.
 *
 * Todas las conexiones entrantes se manejarán en éste hilo.
 *
 * Se descargará en otro hilos las operaciones bloqueantes (resolución de
 * DNS utilizando getaddrinfo), pero toda esa complejidad está oculta en
 * el selector.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "lib/headers/args.h"
#include "lib/headers/stats.h"

#include "lib/headers/selector.h"
#include "smtp.h"
#include "manager/server/manager.h"

#define MAX_CONCURRENT_CLIENTS 1024

static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int main(const int argc, char **argv) {
    struct smtpargs args;

    parse_args(argc, argv, &args);

    // no tenemos nada que leer de stdin
    close(0);

    const char *err_msg = NULL;
    selector_status ss = SELECTOR_SUCCESS;
    selector_status ss2 = SELECTOR_SUCCESS;
    fd_selector selector = NULL;

    statsInit();

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(args.smtp_port);

    struct sockaddr_in6 addr_mng;
    memset(&addr_mng, 0, sizeof(addr_mng));
    addr_mng.sin6_family = AF_INET6;
    addr_mng.sin6_addr = in6addr_any;
    addr_mng.sin6_port = htons(args.mng_port);

    const int server = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    const int server_mng = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (server < 0) {
        err_msg = "unable to create socket smtp";
        goto finally;
    }
    if (server_mng < 0) {
        err_msg = "unable to create socket mng";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", args.smtp_port);
    fprintf(stdout, "Listening on UDP port %d\n", args.mng_port);

    const int enabled = 0;

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled));

    setsockopt(server_mng, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int));
    setsockopt(server_mng, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled));

    if (bind(server, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket smtp";
        goto finally;
    }

    if (listen(server, 20) < 0) {
        err_msg = "unable to listen on smtp socket";
        goto finally;
    }

    if (bind(server_mng, (struct sockaddr *) &addr_mng, sizeof(addr_mng)) < 0) {
        err_msg = "unable to bind socket mng";
        goto finally;
    }

    // registrar sigterm es útil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler); // Para CTRL+D y CTRL+C
    signal(SIGINT, sigterm_handler);

    if (selector_fd_set_nio(server) == -1 || selector_fd_set_nio(server_mng) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    const struct selector_init conf = {
            .signal = SIGALRM,
            .select_timeout = {
                    .tv_sec  = 10,
                    .tv_nsec = 0,
            },
    };
    if (0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if (selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }
    const struct fd_handler smtp = {
            .handle_read       = smtp_passive_accept,
            .handle_write      = NULL,
            .handle_close      = NULL, // nada que liberar
    };
    const struct fd_handler mng = {
            .handle_read       = manager_passive_accept,
            .handle_write      = NULL,
            .handle_close      = NULL, // nada que liberar
    };

    ss = selector_register(selector, server, &smtp, OP_READ, args.transformations);
    if (ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }
    ss2 = selector_register(selector, server_mng, &mng, OP_READ, args.password);
    if (ss2 != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }
    for (; !done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
        ss2 = selector_select(selector);
        if (ss2 != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if (err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
finally:
    if (ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss == SELECTOR_IO
                ? strerror(errno)
                : selector_error(ss));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if (ss2 != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "" : err_msg,
                ss2 == SELECTOR_IO
                ? strerror(errno)
                : selector_error(ss2));
        ret = 2;
    } else if (err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if (selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    //socksv5_pool_destroy();
    //smtp_pool_destroy();

    if (server >= 0) {
        close(server);
    }
    if (server_mng >= 0) {
        close(server_mng);
    }
    return ret;
}
