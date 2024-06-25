#include "smtp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "lib/headers/buffer.h"
#include "lib/headers/stm.h"
#include "lib/headers/request.h"
#include <strings.h>
#include "lib/headers/data.h"
#include "lib/headers/stats.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/time.h>

#define MAIL_FOLDER "maildir"

#define N(x) (sizeof(x)/sizeof(x[0]))
#define MIN(a, b) (((a)<(b))?(a):(b))
#define MAX_RCPT_TO 2
#define DOMAIN_NAME_SIZE 255
#define BUFFER_SIZE 2048
#define BLOCK_SIZE 5
#define DOMAIN "mydomain.com"

/** obtiene el struct (smtp *) desde la llave de selección **/
#define ATTACHMENT(key) ((struct smtp *)(key)->data)

struct smtp {
    /** información del cliente */
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;

    /** maquinas de estados */
    struct state_machine stm;

    /** parsers */
    struct request request;
    struct request_parser request_parser;
    struct data_parser data_parser;

    /** buffers */
    uint8_t raw_buff_read[BUFFER_SIZE], raw_buff_write[BUFFER_SIZE], raw_buff_file[BUFFER_SIZE];
    buffer read_buffer, write_buffer, file_buffer;

    bool go_to_next;
    bool go_to_rcpt_to;
    char mail_from[DOMAIN_NAME_SIZE];
    //char mail_to[MAX_RCPT_TO][DOMAIN_NAME_SIZE];
    char **mail_to;
    int mail_to_index;
    int file_fd;
};

/** maquina de estados general */
enum smtp_state {
    /**
     * escribe el mensaje de bienvenida
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_EHLO cuando se completa el mensaje
     *    - ERROR        ante cualquier error
     */
    WELCOME,
    /**
     * espera el saludo del cliente (EHLO o HELO)
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - WAITING_EHLO      mientras no se reciba el saludo
     *    - RESPONSE_EHLO     cuando se recibe el saludo
     *    - QUIT              cuando se recibe el comando QUIT
     *    - ERROR             ante cualquier error (IO/parseo)
     */
    WAITING_EHLO,
    /**
     * escribir respuesta del EHLO
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_MAIL_FROM cuando se completa la respuesta
     *    - ERROR             ante cualquier error
     */
    RESPONSE_EHLO,
    /**
     * espera el 'mail from' del cliente
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - WAITING_MAIL_FROM  mientras no se reciba el 'mail from'
     *    - RESPONSE_MAIL_FROM cuando se recibe el 'mail from'
     *    - QUIT               cuando se recibe el comando QUIT
     *    - ERROR              ante cualquier error (IO/parseo)
     */
    WAITING_MAIL_FROM,
    /**
     * escribir respuesta del MAIL FROM
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_RCPT_TO cuando se completa la respuesta
     *    - ERROR           ante cualquier error
     */
    RESPONSE_MAIL_FROM,
    /**
     * espera el 'rcpt to' del cliente
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - WAITING_RCPT_TO  mientras no se reciba el 'rcpt to'
     *    - RESPONSE_RCPT_TO cuando se recibe el 'rcpt to'
     *    - QUIT             cuando se recibe el comando QUIT
     *    - ERROR            ante cualquier error (IO/parseo)
     */
    WAITING_RCPT_TO,
    /**
     * escribe la respuesta del RCPT TO
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_DATA cuando se completa la respuesta
     *    - ERROR        ante cualquier error
     */
    RESPONSE_RCPT_TO,
    /**
     * espera el 'data' del cliente
     *
     * Intereses:
     *    - OP_READ sobre client_fd
     *
     * Transiciones:
     *    - RESPONSE_RCPT_TO cuando se recibe 'rcpt to'
     *    - RESPONSE_DATA    cuando se recibe 'data'
     *    - QUIT             cuando se recibe el comando QUIT
     *    - ERROR            ante cualquier error (IO/parseo)
     */
    WAITING_DATA,
    /**
     * escribe respuesta del DATA
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - DATA_READ cuando se completa la respuesta
     *    - ERROR     ante cualquier error
     */
    RESPONSE_DATA,
    /**
	 * lee la data del cliente.
	 *
	 * Intereses:
	 *    - OP_READ sobre client_fd
	 *
     * Transiciones:
     *    - DATA_READ          mientras haya cosas para leer
     *    - DATA_WRITE         cuando se completa la lectura
     *    - ERROR              ante cualquier error (IO/parseo)
	 */
    DATA_READ,
    /**
	 * escribe la data en el archivo.
	 *
	 * Intereses:
     *    - NOP      sobre client_fd
	 *    - OP_WRITE sobre archivo_fd
	 *
     * Transiciones:
     *    - RESPONSE_DATA_WRITE cuando se completa la escritura
     *    - ERROR               ante cualquier error
	 */
    DATA_WRITE,
    /**
     * escribe la respuesta de la escritura de la data
     *
     * Intereses:
     *    - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *    - WAITING_MAIL_FROM cuando se completa la respuesta
     *    - ERROR             ante cualquier error
     */
    RESPONSE_DATA_WRITE,
    /**
     * cierra la conexión
     *
     * Intereses:
     *    - NINGUNO
     *
     * Transiciones:
     *    - NINGUNA
     */
    QUIT,
    // estados terminales
    DONE,
    ERROR,
};

static bool valid_mail_address(char *mail) {
    size_t required_domain_length = strlen(DOMAIN);
    size_t mail_length = strlen(mail);

    // si es de la forma <user@mydomain.com> lo paso a que sea solo user@mydomain.com
    if (mail[0] == '<' && mail[mail_length - 1] == '>') {
        mail++; // salteo el <, el mail ahora apunta al primer caracter del mail
        mail_length -= 2; // salteo el < y el >
        mail[mail_length] = '\0'; // salteo el >
    }

    if (mail_length < required_domain_length || strcmp(mail + mail_length - required_domain_length, DOMAIN) != 0)
        return false;

    // considero un mail no válido si no tiene un @, o si tiene más de un @ o si contiene espacios
    if (strchr(mail, '@') == NULL || strchr(mail, '@') != strrchr(mail, '@') || strchr(mail, ' ') != NULL)
        return false;

    // considero invalido un mail que tiene en algun momento el patron ".."
    for (long unsigned int i = 0; i < strlen(mail) - 1; i++) {
        if (mail[i] == '.' && mail[i + 1] == '.') {
            return false;
        }
    }

    // considero invalido un mail que comienza o termina con un punto o que tiene .@
    if (mail[0] == '.' || mail[strlen(mail) - 1] == '.' || strstr(mail, ".@") != NULL)
        return false;

    // considero un mail no válido si no tiene un punto después del @ o si termina con un @
    if (strchr(strchr(mail, '@'), '.') == NULL || mail[strlen(mail) - 1] == '@')
        return false;

    // considero un mail no válido si comienza con un @
    if (mail[0] == '@')
        return false;

    return true;
}

static void smtp_done(struct selector_key *key);

static void free_mail_to(struct smtp *state) {
    for (int i = 0; i < state->mail_to_index; i++) {
        free(state->mail_to[i]);
    }
    if (state->mail_to != NULL)
        free(state->mail_to);
}

static void request_read_init(const unsigned s, struct selector_key *key) {
    struct request_parser *p = &ATTACHMENT(key)->request_parser;
    p->request = &ATTACHMENT(key)->request;
    request_parser_init(p);
}

static void data_read_init(const unsigned s, struct selector_key *key) {
    struct data_parser *p = &ATTACHMENT(key)->data_parser;
    data_parser_init(p);
}

static void save_response(struct smtp *state, char *message) {
    size_t count;
    uint8_t *ptr;
    ptr = buffer_write_ptr(&state->write_buffer, &count);

    const size_t len = MIN(strlen(message), count);
    strncpy((char *) ptr, message, len);
    buffer_write_adv(&state->write_buffer, len);
}

static bool arg1_is_empty(struct smtp *state) {
    if (strlen(state->request_parser.request->arg1) == 0
        || strspn(state->request_parser.request->arg1, " ") == strlen(state->request_parser.request->arg1)) {
        return true;
    }
    return false;
}

static bool request_process(struct smtp *state, unsigned current_state) {
    if (strcasecmp(state->request_parser.request->verb, "QUIT") == 0
        && (strlen(state->request_parser.request->arg1) == 0)) {
        save_response(state, "221 Bye\n");
        return false;
    }

    switch (current_state) {
        case WAITING_EHLO:
            if (strcasecmp(state->request_parser.request->verb, "EHLO") == 0 ||
                strcasecmp(state->request_parser.request->verb, "HELO") == 0) {
                save_response(state, "250 server at your service\n");
                state->go_to_next = true;
            } else {
                save_response(state, "EHLO/HELO first is expected!\n");
            }
            break;
        case WAITING_MAIL_FROM:
            if (strcasecmp(state->request_parser.request->verb, "MAIL FROM") == 0) {
                if (arg1_is_empty(state)) {
                    save_response(state, "555 Syntax error in parameters or arguments\n");
                    break;
                }
                if (state->request_parser.request->arg1[0] == '<' && state->request_parser.request->arg1[strlen(
                        state->request_parser.request->arg1) - 1] == '>') {
                    memmove(state->request_parser.request->arg1, state->request_parser.request->arg1 + 1,
                            strlen(state->request_parser.request->arg1) - 2);
                    state->request_parser.request->arg1[strlen(state->request_parser.request->arg1) - 2] = '\0';
                }
                if (!valid_mail_address(state->request_parser.request->arg1)) {
                    save_response(state, "555 Syntax error, invalid mail address\n");
                    break;
                }
                strcpy(state->mail_from, state->request_parser.request->arg1);
                save_response(state, "250 OK\n");
                state->go_to_next = true;
            } else {
                save_response(state, "Bad sequence of commands! MAIL FROM: is expected\n");
            }
            break;
        case WAITING_RCPT_TO:
            if (strcasecmp(state->request_parser.request->verb, "RCPT TO") == 0) {
                if (state->mail_to_index != 0) {
                    free_mail_to(state);
                    state->mail_to_index = 0;
                }
                if (arg1_is_empty(state)) {
                    save_response(state, "555 Syntax error, RCPT TO must have an argument\n");
                    break;
                }
                if (state->request_parser.request->arg1[0] == '<' && state->request_parser.request->arg1[strlen(
                        state->request_parser.request->arg1) - 1] == '>') {
                    memmove(state->request_parser.request->arg1, state->request_parser.request->arg1 + 1,
                            strlen(state->request_parser.request->arg1) - 2);
                    state->request_parser.request->arg1[strlen(state->request_parser.request->arg1) - 2] = '\0';
                }
                if (!valid_mail_address(state->request_parser.request->arg1)) {
                    save_response(state, "555 Syntax error, invalid mail address\n");
                    break;
                }
                state->mail_to = malloc(BLOCK_SIZE * sizeof(char *));
                state->mail_to[state->mail_to_index] = malloc(
                        (strlen(state->request_parser.request->arg1) + 1) * sizeof(char));
                strcpy(state->mail_to[state->mail_to_index], state->request_parser.request->arg1);
                save_response(state, "250 OK\n");
                state->go_to_next = true;
                state->mail_to_index++;
            } else {
                save_response(state, "Bad sequence of commands! RCPT TO: is expected\n");
            }
            break;
        case WAITING_DATA:
            if (strcasecmp(state->request_parser.request->verb, "DATA") == 0) {
                if (!arg1_is_empty(state)) {
                    save_response(state, "501 Syntax error, DATA must not have an argument\n");
                    break;
                }
                save_response(state, "354 Start mail input; end with <CRLF>.<CRLF>\n");
                state->go_to_next = true;
            } else if (strcasecmp(state->request_parser.request->verb, "RCPT TO") == 0) {
                if (arg1_is_empty(state)) {
                    save_response(state, "555 Syntax error, RCPT TO must have an argument\n");
                    break;
                }
                if (state->request_parser.request->arg1[0] == '<' && state->request_parser.request->arg1[strlen(
                        state->request_parser.request->arg1) - 1] == '>') {
                    memmove(state->request_parser.request->arg1, state->request_parser.request->arg1 + 1,
                            strlen(state->request_parser.request->arg1) - 2);
                    state->request_parser.request->arg1[strlen(state->request_parser.request->arg1) - 2] = '\0';
                }
                if (!valid_mail_address(state->request_parser.request->arg1)) {
                    save_response(state, "555 Syntax error, invalid mail address\n");
                    break;
                }
                for (int i = 0; i < state->mail_to_index && i < MAX_RCPT_TO; i++) {
                    if (strcmp(state->mail_to[i], state->request_parser.request->arg1) == 0) {
                        save_response(state, "recipient already added\n");
                        state->go_to_rcpt_to = true;
                        state->go_to_next = true;
                        return true;
                    }
                    if (i == MAX_RCPT_TO - 1) {
                        save_response(state, "Maximum number of recipients reached\n");
                        state->go_to_rcpt_to = true;
                        state->go_to_next = true;
                        return true;
                    }
                }
                if (state->mail_to_index % BLOCK_SIZE == 0) {
                    state->mail_to = realloc(state->mail_to, (state->mail_to_index + BLOCK_SIZE) * sizeof(char *));
                }
                state->mail_to[state->mail_to_index] = malloc(
                        (strlen(state->request_parser.request->arg1) + 1) * sizeof(char));
                strcpy(state->mail_to[state->mail_to_index], state->request_parser.request->arg1);
                save_response(state, "250 OK\n");
                state->go_to_rcpt_to = true;
                state->go_to_next = true;
                state->mail_to_index++;
            } else {
                save_response(state, "Bad sequence of commands! DATA is expected\n");
            }
            break;
        default:
            return false;
            break;
    }

    return
            true;
}

static unsigned
request_read2(struct selector_key *key, struct smtp *state, unsigned current_state, unsigned next_state) {
    bool error = false;

    int st = request_consume(&state->read_buffer, &state->request_parser, &error);
    if (request_is_done(st, 0)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
            if (request_process(state, current_state))
                return next_state;
            else
                return QUIT;
        } else {
            return ERROR;
        }
    }
    return current_state;
}

static unsigned request_read(struct selector_key *key, unsigned current_state, unsigned next_state) {
    struct smtp *state = ATTACHMENT(key);
    state->go_to_next = false;

    if (buffer_can_read(&state->read_buffer)) {
        return request_read2(key, state, current_state, next_state);
    } else {
        size_t count;
        uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
        ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);

        bytesReceived(n);

        if (n > 0) {
            buffer_write_adv(&state->read_buffer, n);
            return request_read2(key, state, current_state, next_state);
        } else {
            return false;
        }
    }
}

static unsigned read_data2(struct selector_key *key, struct smtp *state, unsigned current_state, unsigned next_state) {
    bool error = false;

    enum data_state st = data_consume(&state->read_buffer, &state->data_parser, &error);
    if (data_is_done(st)) {
        if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE))
            return next_state;
        else
            return ERROR;
    }
    return DATA_READ;
}

static unsigned read_data(struct selector_key *key, unsigned current_state, unsigned next_state) {
    struct smtp *state = ATTACHMENT(key);

    if (buffer_can_read(&state->read_buffer)) {
        return read_data2(key, state, current_state, next_state);
    } else {
        size_t count;
        uint8_t *ptr = buffer_write_ptr(&state->read_buffer, &count);
        ssize_t n = recv(key->fd, ptr, count, MSG_DONTWAIT);

        bytesReceived(n);

        if (n > 0) {
            buffer_write_adv(&state->read_buffer, n);
            return read_data2(key, state, current_state, next_state);
        } else {
            return ERROR;
        }
    }
}

static unsigned response_write(struct selector_key *key, unsigned current_state, unsigned next_state) {
    unsigned ret = current_state;

    size_t count;
    buffer *wb = &ATTACHMENT(key)->write_buffer;

    uint8_t *ptr = buffer_read_ptr(wb, &count);
    ssize_t n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    bytesSent(n);

    if (n >= 0) {
        buffer_read_adv(wb, n);
        if (!buffer_can_read(wb)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                ret = next_state;
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return ret;
}

static unsigned welcome(struct selector_key *key) {
    return response_write(key, WELCOME, WAITING_EHLO);
}

static unsigned waiting_ehlo(struct selector_key *key) {
    return request_read(key, WAITING_EHLO, RESPONSE_EHLO);
}

static unsigned response_ehlo(struct selector_key *key) {
    if (response_write(key, RESPONSE_EHLO, WAITING_MAIL_FROM) == WAITING_MAIL_FROM
        && ATTACHMENT(key)->go_to_next)
        return WAITING_MAIL_FROM;
    return WAITING_EHLO;
}

static unsigned waiting_mail_from(struct selector_key *key) {
    return request_read(key, WAITING_MAIL_FROM, RESPONSE_MAIL_FROM);
}

static unsigned response_mail_from(struct selector_key *key) {
    if (response_write(key, RESPONSE_MAIL_FROM, WAITING_RCPT_TO) == WAITING_RCPT_TO
        && ATTACHMENT(key)->go_to_next)
        return WAITING_RCPT_TO;
    return WAITING_MAIL_FROM;
}

static unsigned waiting_rcpt_to(struct selector_key *key) {
    return request_read(key, WAITING_RCPT_TO, RESPONSE_RCPT_TO);
}

static unsigned response_rcpt_to(struct selector_key *key) {
    if (response_write(key, RESPONSE_RCPT_TO, WAITING_DATA) == WAITING_DATA
        && ATTACHMENT(key)->go_to_next)
        return WAITING_DATA;
    return WAITING_RCPT_TO;
}

static unsigned waiting_data(struct selector_key *key) {
    ATTACHMENT(key)->go_to_rcpt_to = false;
    unsigned ret = request_read(key, WAITING_DATA, RESPONSE_DATA);
    if (ATTACHMENT(key)->go_to_rcpt_to)
        ret = RESPONSE_RCPT_TO;
    return ret;
}

static unsigned response_data(struct selector_key *key) {
    if (response_write(key, RESPONSE_DATA, DATA_READ) == DATA_READ
        && ATTACHMENT(key)->go_to_next)
        return DATA_READ;
    return WAITING_DATA;
}

static unsigned data_read(struct selector_key *key) {
    return read_data(key, DATA_READ, DATA_WRITE);
}

static unsigned data_write(struct selector_key *key) {
    struct smtp *state = ATTACHMENT(key);

    if (mkdir(MAIL_FOLDER, 0777) == -1) {
        if (errno != EEXIST) {
            perror("mkdir");
            return ERROR;
        }
    }

    size_t count;
    uint8_t *ptr = buffer_read_ptr(&state->data_parser.output_buffer, &count);

    for (int i = 0; i < state->mail_to_index; i++) {
        char p[DOMAIN_NAME_SIZE];

        // maildir
        //       |--- user
        //       |       |--- cur
        //       |       |--- tmp
        //       |       |--- new
        //       |--- user2
        //               |--- cur
        //               |--- tmp
        //               |--- new
        // Descripción de cada carpeta:
        // cur: Contiene los correos electrónicos que han sido leídos.
        // tmp: Contiene correos electrónicos que están siendo procesados.
        // new: Contiene correos electrónicos nuevos que aún no han sido leídos.

        strcpy(p, MAIL_FOLDER);
        strcat(p, "/");
        strcat(p, state->mail_to[i]);
        if (mkdir(p, 0777) == -1) {
            if (errno != EEXIST) {
                perror("mkdir");
                return ERROR;
            }
        }

        strcpy(p, MAIL_FOLDER);
        strcat(p, "/");
        strcat(p, state->mail_to[i]);
        strcat(p, "/cur");
        if (mkdir(p, 0777) == -1) {
            if (errno != EEXIST) {
                perror("mkdir");
                return ERROR;
            }
        }

        strcpy(p, MAIL_FOLDER);
        strcat(p, "/");
        strcat(p, state->mail_to[i]);
        strcat(p, "/new");
        if (mkdir(p, 0777) == -1) {
            if (errno != EEXIST) {
                perror("mkdir");
                return ERROR;
            }
        }

        strcpy(p, MAIL_FOLDER);
        strcat(p, "/");
        strcat(p, state->mail_to[i]);
        strcat(p, "/tmp");
        if (mkdir(p, 0777) == -1) {
            if (errno != EEXIST) {
                perror("mkdir");
                return ERROR;
            }
        }

        strcpy(p, MAIL_FOLDER);
        strcat(p, "/");
        strcat(p, state->mail_to[i]);
        strcat(p, "/tmp/");
        time_t t = time(NULL);
        struct tm tm = *localtime(&t);
        char date[72];
        sprintf(date, "%d-%02d-%02d_%02d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour,
                tm.tm_min, tm.tm_sec);
        strcat(p, date);
        strcat(p, ".txt");

        state->file_fd = open(p, O_CREAT | O_WRONLY | O_APPEND, 0777);
        if (state->file_fd == -1) return ERROR;

        char to_send[DOMAIN_NAME_SIZE + 80] = "From ";
        strcat(to_send, state->mail_from);
        // tengo que poner la fecha en formato "Day, Month Date, Hour:Minute:Second Year"
        char date_formatted[72];
        time_t rawtime;
        struct tm *tm_info;
        time(&rawtime);
        tm_info = localtime(&rawtime);
        strftime(date_formatted, sizeof(date_formatted), " %a %b %d %H:%M:%S %Y", tm_info);
        strcat(to_send, date_formatted);
        strcat(to_send, "\r\n");

        // Open log.txt and write the desired information
        int log_fd = open("log.txt", O_CREAT | O_WRONLY | O_APPEND, 0777);
        if (log_fd == -1) {
            perror("open log.txt");
            return ERROR;
        }
        char log_message[DOMAIN_NAME_SIZE + 100] = "from: ";
        strcat(log_message, date_formatted);
        strcat(log_message, " ||| ");
        strcat(log_message, date);
        strcat(log_message, " ||| ");
        strcat(log_message, state->mail_from);

        strcat(log_message, "\n");
        if (write(log_fd, log_message, strlen(log_message)) == -1) {
            perror("write to log.txt");
            close(log_fd);
            return ERROR;
        }
        close(log_fd);

        if (write(state->file_fd, to_send, strlen(to_send)) == -1) return ERROR;
    }

    ssize_t n = write(state->file_fd, ptr, count);

    if (n >= 0) {
        buffer_read_adv(&state->data_parser.output_buffer, n);
        if (data_is_done(state->data_parser.state)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                save_response(state, "250 OK\n");
                return RESPONSE_DATA_WRITE;
            } else {
                return ERROR;
            }
        }
    } else {
        return ERROR;
    }
    return DATA_WRITE;
}

static unsigned response_data_write(struct selector_key *key) {
    if (response_write(key, RESPONSE_DATA_WRITE, WAITING_MAIL_FROM) == WAITING_MAIL_FROM)
        return WAITING_MAIL_FROM;
    return ERROR;
}

static unsigned quit(struct selector_key *key) {
    if (response_write(key, QUIT, DONE) == DONE)
        return DONE;
    return ERROR;
}

/** definición de handlers para cada estado */
static const struct state_definition client_statbl[] = {
        {
                .state            = WELCOME,
                .on_write_ready   = welcome,
        },
        {
                .state            = WAITING_EHLO,
                .on_arrival       = request_read_init,
                .on_read_ready    = waiting_ehlo,
        },
        {
                .state            = RESPONSE_EHLO,
                .on_write_ready   = response_ehlo,
        },
        {
                .state            = WAITING_MAIL_FROM,
                .on_arrival       = request_read_init,
                .on_read_ready    = waiting_mail_from,
        },
        {
                .state            = RESPONSE_MAIL_FROM,
                .on_write_ready   = response_mail_from,
        },
        {
                .state            = WAITING_RCPT_TO,
                .on_arrival       = request_read_init,
                .on_read_ready    = waiting_rcpt_to,
        },
        {
                .state            = RESPONSE_RCPT_TO,
                .on_write_ready   = response_rcpt_to,
        },
        {
                .state            = WAITING_DATA,
                .on_arrival       = request_read_init,
                .on_read_ready    = waiting_data,
        },
        {
                .state            = RESPONSE_DATA,
                .on_write_ready   = response_data,
        },
        {
                .state            = DATA_READ,
                .on_arrival       = data_read_init,
                .on_read_ready    = data_read,
        },
        {
                .state            = DATA_WRITE,
                .on_write_ready   = data_write,
        },
        {
                .state            = RESPONSE_DATA_WRITE,
                .on_write_ready   = response_data_write,
        },
        {
                .state            = QUIT,
                .on_write_ready   = quit,
        },
        {
                .state = DONE,
        },
        {
                .state = ERROR,
        },
};

/* declaración forward de los handlers de selección de una conexión
 * establecida entre un cliente y el proxy.
 */
static void smtp_read(struct selector_key *key);

static void smtp_write(struct selector_key *key);

static void smtp_close(struct selector_key *key);

static const struct fd_handler smtp_handler = {
        .handle_read   = smtp_read,
        .handle_write  = smtp_write,
        .handle_close  = smtp_close,
};

///////////////////////////////////////////////////////////////////////////////
// Handlers top level de la conexión pasiva.
// son los que emiten los eventos a la maquina de estados.

static void smtp_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum smtp_state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st) {
        smtp_done(key);
    }
}

static void smtp_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum smtp_state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st) { // si hubo un error, cierro la conexión
        smtp_done(key);
    } else if (WAITING_EHLO == st || WAITING_MAIL_FROM == st || WAITING_RCPT_TO == st || WAITING_DATA == st ||
               DATA_READ == st) {
        buffer *rb = &ATTACHMENT(key)->read_buffer;
        if (buffer_can_read(rb)) {
            smtp_read(key); // si hay para leer en el buffer sigo leyendo sin quedarme bloqueado
        }
    }
}

static void smtp_done(struct selector_key *key) {
    if (key->fd != -1) {
        if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, key->fd)) {
            abort();
        }
        close(key->fd);
    }
}

static void smtp_destroy(struct smtp *state) {
    free_mail_to(state);
    free(state);
}

static void smtp_close(struct selector_key *key) {
    if (ATTACHMENT(key)->file_fd != -1) {
        close(ATTACHMENT(key)->file_fd);
    }
    userDisconnection();
    smtp_destroy(ATTACHMENT(key));
}

/** Intenta aceptar la nueva conexión entrante*/
void smtp_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct smtp *state = NULL;

    const int client = accept(key->fd, (struct sockaddr *) &client_addr, &client_addr_len);
    if (client == -1) {
        goto fail;
    }
    if (selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = malloc(sizeof(struct smtp));
    if (state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberó alguna conexión.
        goto fail;
    }

    newUserConnection();

    memset(state, 0, sizeof(*state));
    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    state->file_fd = -1;
    state->stm.initial = WELCOME;
    state->mail_to_index = 0;
    state->stm.max_state = ERROR;
    state->stm.states = client_statbl;
    stm_init(&state->stm);

    buffer_init(&state->read_buffer, N(state->raw_buff_read), state->raw_buff_read);
    buffer_init(&state->write_buffer, N(state->raw_buff_write), state->raw_buff_write);

    char *message = "220 Service Ready\n";
    uint8_t len = strlen(message);

    memcpy(&state->raw_buff_write, message, len);
    buffer_write_adv(&state->write_buffer, len);

    state->request_parser.request = &state->request;
    request_parser_init(&state->request_parser);

    data_parser_init(&state->data_parser);

    if (SELECTOR_SUCCESS != selector_register(key->s, client, &smtp_handler, OP_WRITE, state)) {
        goto fail;
    }
    return;
    fail:
    if (client != -1) {
        close(client);
    }
    smtp_destroy(state);
}
