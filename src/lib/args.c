#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>

#include "headers/args.h"

static unsigned short
port(const char *s) {
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short) sl;
}

static void
version(void) {
    fprintf(stderr, "smtp version 0.0\n"
                    "ITBA Protocolos de Comunicación 2024/1 -- Grupo 11\n"
                    "Deyheralde, Ben - Mutz, Matías - Ves Losada, Tobías"
                    "AQUI VA LA LICENCIA\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <SMTP addr>   Dirección donde servirá el SMTP.\n"
            "   -L <conf addr>   Dirección donde servirá el servicio de management.\n"
            "   -p <SMTP port>   Puerto entrante conexiones SMTP.\n"
            "   -P <conf port>   Puerto entrante conexiones configuracion\n"
            "   -u <password>    Password para rol de administrador, 8 caracteres.\n"
            "   -T <program>     Prende las transformaciones con el programa indicado.\n"
            "   -v               Imprime información sobre la versión versión y termina.\n"
            "\n",
            progname);
    exit(1);
}

void
parse_args(const int argc, char **argv, struct smtpargs *args) {
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->smtp_addr = "0.0.0.0";
    args->smtp_port = 2525;

    args->mng_addr = "127.0.0.1";
    args->mng_port = 7374;

    args->disectors_enabled = true;

    args->password = "password";

    int c;

    while (true) {
        int option_index = 0;
        static struct option long_options[] = {
                {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hl:L:Np:P:u:vT:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                args->smtp_addr = optarg;
                break;
            case 'T':
                args->transformations = optarg;
                break;
            case 'L':
                args->mng_addr = optarg;
                break;
            case 'N':
                args->disectors_enabled = false;
                break;
            case 'p':
                args->smtp_port = port(optarg);
                break;
            case 'P':
                args->mng_port = port(optarg);
                break;
            case 'u':
                args->password = optarg;
                break;
            case 'v':
                version();
                exit(0);
                break;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
