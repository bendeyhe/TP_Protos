#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

/*
 * Vamos a popular esta struct desde la linea de comandos.
 * - Lista de hosts de dominios que aceptamos.
 * - Directorio raiz donde vamos a guardar los correos.
 * - Puerto default del protocolo SMTP y del protocolo de management.
 * - SockAddr para definir si bindeamos a localhost o no.
 */
struct smtpargs {
    char *mail_directory;

    char *smtp_addr;
    unsigned short smtp_port;

    char *mng_addr;
    unsigned short mng_port;

    bool disectors_enabled;

    char *transformations;

    char * password;
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecución.
 */
void
parse_args(const int argc, char **argv, struct smtpargs *args);

#endif

